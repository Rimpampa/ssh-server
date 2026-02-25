// mod pty;

mod db;
use db::Database;

use anyhow::Context;

use std::ffi::CString;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::server::{Auth, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Mutex;

use uzers::os::unix::UserExt;

use libc;

use nix::pty::{OpenptyResult, Winsize};
use nix::unistd::{ForkResult, Gid, Uid, dup2, execv, fork, setgid, setsid, setuid};

use log::{debug, error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    info!("SSH Server starting");

    // Ensure we can change uid/gid — this server must run as root to start sessions as other users
    if !nix::unistd::Uid::effective().is_root() {
        error!("Server must be run as root to spawn shells as other users");
        anyhow::bail!("Server must be run as root to spawn shells as other users");
    }
    info!("Root privileges verified");

    let key = std::env::args().nth(1).with_context(|| "Missing key")?;
    debug!("Loading SSH private key from: {}", key);
    let key = tokio::fs::read_to_string(key).await?;
    let key = PrivateKey::from_openssh(key)?;
    info!("SSH private key loaded successfully");

    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_secs(0),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let listener = TcpListener::bind("0.0.0.0:2222").await?;
    info!("SSH Server listening on 0.0.0.0:2222");

    let db = Database::new();
    loop {
        let (stream, addr) = listener.accept().await?;
        let ip = addr.ip();
        info!("New connection from {ip}");

        match db.connected(ip) {
            Ok(()) => info!("Connection from {ip} registered"),
            Err(e) => {
                error!("Connection rejected from {ip}: {e}");
                continue;
            }
        };

        let config = config.clone();
        let db = db.clone();
        tokio::spawn(async move {
            debug!("Starting SSH session handler for {ip}");
            russh::server::run_stream(config, stream, Connection::new(db.clone(), ip))
                .await?
                .await?;
            info!("SSH session ended for {ip}");
            db.disconnected(ip);
            info!("Disconnected {ip}");
            Result::<(), anyhow::Error>::Ok(())
        });
    }
}

#[derive(Clone)]
struct Connection {
    db: Database,
    ip: IpAddr,
    // child's stdin as an async file (parent writes to this to send data to child)
    stdin: Arc<Mutex<Option<tokio::fs::File>>>,
    // PTY negotiated size (cols, rows)
    pty_size: Option<Winsize>,
    // terminal name (TERM)
    pty_term: Option<String>,
    // raw master fd for ioctl window changes (use duplicated fd)
    pty_master_fd: Option<i32>,
}

impl Connection {
    fn new(db: Database, ip: IpAddr) -> Self {
        Self {
            db,
            ip,
            stdin: Default::default(),
            pty_size: None,
            pty_term: None,
            pty_master_fd: None,
        }
    }
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        info!("Authentication attempt for user: {user}");

        if let Err(e) = self.db.authorized(self.ip, user) {
            warn!("Authentication failed for user {user}: {e}");
            return Ok(Auth::reject());
        };

        if let None = uzers::get_user_by_name(user) {
            info!("User {user} does not exist, creating...");
            let status = Command::new("useradd").arg("-m").arg(user).status().await?;
            if !status.success() {
                error!("useradd failed for user {user}");
                anyhow::bail!("useradd failed");
            }
            info!("User {user} created successfully");
        } else {
            info!("User {user} already exists");
        }

        info!("Authentication accepted for user {user}");
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
        info!(
            "PTY request for channel {channel}: term={term}, cols={col_width}, rows={row_height}",
        );

        self.pty_size = Some(Winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        });
        self.pty_term = Some(term.to_string());
        session.channel_success(channel)?;

        info!("PTY allocated successfully for channel {channel}");
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
        info!("Window change request for channel {channel}: cols={col_width}, rows={row_height}",);

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
            debug!("Window resized for channel {channel}");
        } else {
            warn!("Window change requested but no master fd available for channel {channel}",);
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
        let channel_id = channel.id();
        info!("Channel open session request for channel {channel_id}");

        let Some(user) = self.db.user(self.ip) else {
            warn!("Channel open session failed: no username set for channel {channel_id}",);
            return Ok(false);
        };
        let Some(user) = uzers::get_user_by_name(&*user) else {
            warn!("Channel open session failed: user not found for channel {channel_id}",);
            return Ok(false);
        };
        let home = user.home_dir().to_owned();

        // allocate a PTY for interactive session using requested size if any
        let OpenptyResult { master, slave } = nix::pty::openpty(self.pty_size.as_ref(), None)?;
        debug!("PTY allocated: master={master:?}, slave={slave:?}");

        // SAFETY: TODO
        match unsafe { fork()? } {
            ForkResult::Child => {
                let slave = slave.into_raw_fd();
                debug!("CHILD - Child process started");
                // Child: become session leader and set up slave PTY as controlling terminal
                let _ = setsid();

                // set controlling tty
                // SAFETY: TODO
                unsafe { libc::ioctl(slave, libc::TIOCSCTTY, 0) };
                debug!("CHILD - Set controlling tty");

                // Drop privileges: initgroups, setgid, setuid
                let uname = CString::new(user.name().as_encoded_bytes()).unwrap();
                let gid_raw = user.primary_group_id();
                let uid_raw = user.uid();
                info!(
                    "CHILD - Setting privileges for user: {:?} (uid={uid_raw}, gid={gid_raw})",
                    user.name(),
                );
                // SAFETY: TODO
                unsafe { libc::initgroups(uname.as_ptr(), gid_raw as libc::gid_t) };
                let _ = setgid(Gid::from_raw(gid_raw));
                let _ = setuid(Uid::from_raw(uid_raw));

                // Redirect stdio to slave PTY
                let _ = dup2(slave, 0);
                let _ = dup2(slave, 1);
                let _ = dup2(slave, 2);

                // SAFETY: TODO
                unsafe {
                    // Setup environment variables for the child process
                    std::env::remove_var("SSH_ASKPASS");
                    std::env::set_var("HOME", &home);
                    std::env::set_var("USER", user.name());
                    std::env::set_var("LOGNAME", user.name());
                    std::env::set_var("SHELL", user.shell());

                    // Set TERM if provided in PTY request
                    if let Some(ref term) = self.pty_term {
                        std::env::set_var("TERM", term);
                    }
                }

                // Change to user's home directory
                let _ = std::env::set_current_dir(&home);
                debug!("CHILD - Changed working directory to {}", home.display());

                // Exec shell (use user's shell)
                let shell_path = user.shell().as_os_str().as_encoded_bytes();
                let shell = CString::new(shell_path).unwrap();
                let arg0 = CString::new(shell_path).unwrap();
                let arg1 = CString::new("-i").unwrap();
                let args = [arg0.as_c_str(), arg1.as_c_str()];
                let _ = execv(shell.as_c_str(), &args);

                error!("CHILD - execv failed, exiting child");
                std::process::exit(1);
            }
            ForkResult::Parent { child } => {
                info!("PRENT - Child process spawned with pid={child}",);

                let master = std::fs::File::from(master);
                let write = tokio::fs::File::from_std(master);
                let read = write.try_clone().await?;
                let read_fd = read.as_raw_fd();

                // Forward pty master output to SSH channel
                info!("PRENT - Starting output forwarder for channel {channel_id}",);
                forward(channel.id(), session.handle(), read);

                // Store write as stdin writer (writes go to master)
                *self.stdin.lock().await = Some(write);

                // Store read_fd for window-change ioctls
                self.pty_master_fd = Some(read_fd);

                // Reap child in background to avoid zombies
                tokio::task::spawn_blocking(move || {
                    let _ = nix::sys::wait::waitpid(child, None);
                    info!("PRENT - Child process {child} reaped");
                });
            }
        }

        session.channel_success(channel.id())?;
        info!("PRENT - Channel {channel_id} session opened successfully");
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Close channel when exit is received
        let cmd = std::str::from_utf8(data).map(str::trim);
        if cmd == Ok("exit") {
            info!("Exit command received on channel {channel}");
            session.disconnect(russh::Disconnect::ByApplication, "User requested exit", "")?;
            return Err(russh::Error::Disconnect.into());
        }

        let mut stdin = self.stdin.lock().await;
        let Some(stdin) = stdin.as_mut() else {
            warn!("Data received but no stdin available for channel {channel}",);
            return Ok(());
        };
        stdin.write_all(data).await?;
        stdin.flush().await?;
        Ok(())
    }
}

fn forward<R: AsyncRead + Unpin + Send + 'static>(id: ChannelId, handle: Handle, reader: R) {
    tokio::spawn(async move {
        debug!("Output forwarder started for channel {id}");
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 1024];
        loop {
            let res = reader.read(&mut buf).await;
            if let Err(e) = &res {
                error!("Output forwarder error on channel {id}: {e}");
            }
            let _ = match res {
                Ok(0) | Err(_) => break,
                Ok(n) => handle.data(id, CryptoVec::from(&buf[..n])).await,
            };
        }
        info!("Output forwarder ended for channel {}", id);
    });
}
