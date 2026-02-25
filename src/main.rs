mod username;
use anyhow::Context;
use username::Username;

mod db;
use db::Database;

use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::server::{Auth, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Mutex;

use uzers::os::unix::UserExt;

use libc;
use nix::pty::Winsize;
use nix::unistd::{ForkResult, close, dup, dup2, execv, fork, setsid};
use nix::unistd::{Gid, Uid, setgid, setuid};
use std::ffi::CString;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Ensure we can change uid/gid — this server must run as root to start sessions as other users
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("Server must be run as root to spawn shells as other users");
    }

    let key = std::env::args().nth(1).with_context(|| "Missing key")?;
    let key = tokio::fs::read_to_string(key).await?;
    let key = PrivateKey::from_openssh(key)?;

    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_secs(0),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let listener = TcpListener::bind("0.0.0.0:2222").await?;
    println!("Listening on 0.0.0.0:2222");

    let db = Database::new();
    loop {
        let (stream, addr) = listener.accept().await?;
        let ip = addr.ip();

        let username = match db.connected(ip) {
            Ok(username) => username,
            Err(e) => {
                println!("ERROR ({ip}): {e}");
                continue;
            }
        };

        let config = config.clone();
        let db = db.clone();
        tokio::spawn(async move {
            let _ = russh::server::run_stream(config, stream, Connection::new(username)).await; // TODO: log
            db.disconnected(ip);
        });
    }
}

#[derive(Clone)]
struct Connection {
    username: Username,
    // child's stdin as an async file (parent writes to this to send data to child)
    stdin: Arc<Mutex<Option<tokio::fs::File>>>,
    // PTY negotiated size (cols, rows)
    pty_size: Option<Winsize>,
    // terminal name (TERM)
    pty_term: Option<String>,
    // raw master fd for ioctl window changes (use duplicated fd)
    pty_master_fd: Option<i32>,
    // Keep PTY alive to prevent fd from being closed
    _pty: Arc<Mutex<Option<nix::pty::OpenptyResult>>>,
}

impl Connection {
    fn new(username: Username) -> Self {
        Self {
            username,
            stdin: Default::default(),
            pty_size: None,
            pty_term: None,
            pty_master_fd: None,
            _pty: Arc::new(Mutex::new(None)),
        }
    }
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if let Err(e) = self.username.set(user) {
            println!("{e}");
            return Ok(Auth::reject());
        };

        if let None = uzers::get_user_by_name(user) {
            let status = Command::new("useradd").arg("-m").arg(user).status().await?;
            if !status.success() {
                anyhow::bail!("useradd failed");
            }
        }
        Ok(Auth::Accept)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty_size = Some(Winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        });
        self.pty_term = Some(term.to_string());
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // attempt to resize PTY if we have a master fd
        if let Some(fd) = self.pty_master_fd {
            let ws = Winsize {
                ws_row: row_height as u16,
                ws_col: col_width as u16,
                ws_xpixel: pix_width as u16,
                ws_ypixel: pix_height as u16,
            };
            // SAFETY: TODO
            unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
            self.pty_size = Some(ws);
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
            // TODO
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self.username.get() else {
            return Ok(false);
        };
        let Some(user) = uzers::get_user_by_name(&*user) else {
            return Ok(false);
        };
        let home = user.home_dir().to_owned();

        // allocate a PTY for interactive session using requested size if any
        let pty = nix::pty::openpty(self.pty_size.as_ref(), None)?;
        let master_fd = pty.master.as_raw_fd();
        let slave_fd = pty.slave.as_raw_fd();

        // Store PTY to keep it alive throughout the session
        *self._pty.lock().await = Some(pty);

        // SAFETY: TODO
        match unsafe { fork()? } {
            ForkResult::Child => {
                // Child: become session leader and set up slave PTY as controlling terminal
                let _ = setsid();

                // set controlling tty
                // SAFETY: TODO
                unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) };

                // Drop privileges: initgroups, setgid, setuid
                let uname = CString::new(user.name().as_encoded_bytes()).unwrap();
                let gid_raw = user.primary_group_id();
                let uid_raw = user.uid();
                // SAFETY: TODO
                unsafe { libc::initgroups(uname.as_ptr(), gid_raw as libc::gid_t) };
                let _ = setgid(Gid::from_raw(gid_raw));
                let _ = setuid(Uid::from_raw(uid_raw));

                // Redirect stdio to slave PTY
                let _ = dup2(slave_fd, 0);
                let _ = dup2(slave_fd, 1);
                let _ = dup2(slave_fd, 2);

                // Change to user's home directory
                let _ = std::env::set_current_dir(&home);

                // Exec shell (use user's shell)
                let shell_path = user.shell().as_os_str().as_encoded_bytes();
                let shell = CString::new(shell_path).unwrap();
                let arg0 = CString::new(shell_path).unwrap();
                let arg1 = CString::new("-i").unwrap();
                let args = [arg0.as_c_str(), arg1.as_c_str()];
                let _ = execv(shell.as_c_str(), &args);

                std::process::exit(1);
            }
            ForkResult::Parent { child } => {
                // Parent: close slave fd and forward IO on master fd
                let _ = close(slave_fd);

                // Duplicate master fd: one fd for reading/forwarding, one for writing
                let read_fd = dup(master_fd)?;
                let write_fd = dup(master_fd)?;

                // SAFETY: TODO
                let read = unsafe { std::fs::File::from_raw_fd(read_fd) };
                // SAFETY: TODO
                let write = unsafe { std::fs::File::from_raw_fd(write_fd) };

                let read = fs::File::from_std(read);
                let write = fs::File::from_std(write);

                // Forward pty master output to SSH channel
                forward(channel.id(), session.handle(), read);

                // Store write as stdin writer (writes go to master)
                *self.stdin.lock().await = Some(write);

                // Store read_fd for window-change ioctls
                self.pty_master_fd = Some(read_fd);

                // Reap child in background to avoid zombies
                tokio::task::spawn_blocking(move || {
                    let _ = nix::sys::wait::waitpid(child, None);
                });
            }
        }

        session.channel_success(channel.id())?;
        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: russh::ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut stdin = self.stdin.lock().await;
        let Some(stdin) = stdin.as_mut() else {
            return Ok(());
        };
        stdin.write_all(data).await?;
        stdin.flush().await?;
        Ok(())
    }
}

fn forward<R: AsyncRead + Unpin + Send + 'static>(id: ChannelId, handle: Handle, reader: R) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = handle.data(id, CryptoVec::from(&buf[..n])).await;
                }
            }
        }
    });
}
