mod db;
use db::Database;

mod pty;
use pty::{Pty, PtyFork};

use anyhow::Context;

use std::ffi::{CString, OsStr};
use std::net::SocketAddr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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

use nix::unistd::{Gid, Uid, setgid, setuid};

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

    // Initialize the environment variables once and share them with all connections to avoid
    // repeated allocations while handling SSH sessions.
    let env = env();

    let listener = TcpListener::bind("0.0.0.0:2222").await?;
    info!("SSH Server listening on 0.0.0.0:2222");

    let db = Database::new();
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("New connection from {addr}");

        let config = config.clone();
        let db = db.clone();
        let env = env.clone();
        tokio::spawn(async move {
            debug!("Starting SSH session handler for {addr}");
            russh::server::run_stream(config, stream, Connection::new(db.clone(), addr, env))
                .await?
                .await?;
            info!("SSH session ended for {addr}");
            db.disconnected(addr);
            info!("Disconnected {addr}");
            Result::<(), anyhow::Error>::Ok(())
        });
    }
}

#[derive(Clone)]
struct Connection {
    db: Database,
    addr: SocketAddr,
    /// Child's stdin as an async file
    stdin: Arc<Mutex<Option<tokio::fs::File>>>,
    pty: Pty,
    env: Arc<Vec<CString>>,
}

impl Connection {
    fn new(db: Database, addr: SocketAddr, env: Arc<Vec<CString>>) -> Self {
        Self {
            db,
            addr,
            stdin: Default::default(),
            pty: Default::default(),
            env,
        }
    }
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!("Authentication attempt for user: {user}");

        if let Err(e) = self.db.authorized(self.addr, user, password) {
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
        col_w: u32,
        row_h: u32,
        pix_w: u32,
        pix_h: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("PTY request for channel {channel}: term={term}, cols={col_w}, rows={row_h}",);
        self.pty.request(col_w, row_h, pix_w, pix_h, term);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_w: u32,
        row_h: u32,
        pix_w: u32,
        pix_h: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Window change request for channel {channel}: cols={col_w}, rows={row_h}",);
        match self.pty.window_change(col_w, row_h, pix_w, pix_h) {
            Ok(()) => session.channel_success(channel)?,
            Err(()) => {
                warn!("Window change requested but no master fd available for channel {channel}",);
                session.channel_failure(channel)?;
            }
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

        let Some(user) = self.db.user(self.addr) else {
            warn!("Channel open session failed: no username set for channel {channel_id}",);
            return Ok(false);
        };
        let Some(user) = uzers::get_user_by_name(&*user) else {
            warn!("Channel open session failed: user not found for channel {channel_id}",);
            return Ok(false);
        };
        let home = user.home_dir().to_owned();

        let child_env = child_env(&user, self.pty.term.as_deref());
        // From man execve(2):
        // > envp is an array of pointers to strings, conventionally of the
        // > form key=value, which are passed as the environment of the new
        // > program.  The envp array must be terminated by a null pointer.
        // NOTE:
        //   Prepare the array of C strings before forking to avoid memory allocation in the
        //   child process, which may not be async-signal-safe (check following SAFETY notice)
        let env: Box<[*const i8]> = self
            .env
            .iter()
            .chain(&child_env)
            .map(|s| s.as_ptr())
            .chain([std::ptr::null()])
            .collect();

        // From execve(2):
        // > argv is an array of pointers to strings passed to the new program
        // > as its command-line arguments.  By convention, the first of these
        // > strings (i.e., argv[0]) should contain the filename associated
        // > with the file being executed.  The argv array must be terminated
        // > by a null pointer.  (Thus, in the new program, argv[argc] will be
        // > a null pointer.)
        // NOTE:
        //   Prepare the array of C strings before forking to avoid memory allocation in the
        //   child process, which may not be async-signal-safe (check following SAFETY notice)
        let shell = CString::new(user.shell().as_os_str().as_bytes()).unwrap();
        let shell = shell.as_ptr();
        let arg = CString::new("-i").unwrap();
        let args = [shell, arg.as_ptr(), std::ptr::null()];

        // allocate a PTY for interactive session using requested size if any
        // SAFETY:
        // From the nix crate (https://docs.rs/nix/latest/nix/unistd/fn.fork.html#safety)
        // > In a multithreaded program, only async-signal-safe functions like pause and _exit may
        // > be called by the child (the parent isn’t restricted) until a call of execve(2). Note
        // > that memory allocation may not be async-signal-safe and thus must be prevented.
        match unsafe { self.pty.open()? } {
            PtyFork::Child => {
                // NOTE: (reference: man signal-safety(7))
                //   All those function (setgid, setuid, chdir) are async-signal-safe according to POSIX,
                //   so it's safe to call them in the child process after fork without execve
                let _ = setgid(Gid::from_raw(user.primary_group_id()));
                let _ = setuid(Uid::from_raw(user.uid()));
                let _ = std::env::set_current_dir(&home); // <-- Calls chdir

                // NOTE: Cannot use nix::unistd::execve since it allocates (not async-signal-safe)
                // SAFETY: all the arguments are constructed coorectly (check above)
                let res = unsafe { libc::execve(shell, args.as_ptr(), env.as_ptr()) };
                let _ = nix::errno::Errno::result(res); // <-- Usually done by nix crate

                std::process::exit(1);
            }
            PtyFork::Parent { fd: master, child } => {
                // NOTE:
                // env must be dropped before the first await point
                // since it holds raw pointers which are not Send
                drop(env);

                let master = std::fs::File::from(master);
                let write = tokio::fs::File::from_std(master);
                let read = write.try_clone().await?;

                info!("PRENT - Starting output forwarder for channel {channel_id}",);
                forward(channel.id(), session.handle(), read);

                *self.stdin.lock().await = Some(write);

                tokio::task::spawn_blocking(move || {
                    let _ = nix::sys::wait::waitpid(child, None);
                    info!("PRENT - Child process {child} reaped");
                    // TODO: close session
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

/// Forward the data coming from the given reader to the SSH session channel until EOF or an error occurs,
/// in which case the channel is closed.
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

/// Helper macro to create a [`CString`] from multiple parts that may be [`OsStr`]
macro_rules! cstring {
    ($f:expr $(, $e:expr)* $(,)?) => {{
        let mut string = OsStr::new($f).to_os_string();
        $(string.push($e);)*
        CString::new(string.into_vec())
    }}
}

/// Create a copy of the current environment variables
fn env() -> Arc<Vec<CString>> {
    Arc::new(
        std::env::vars_os()
            .filter_map(|(k, v)| cstring!(&k, "=", v).ok())
            .collect(),
    )
}

/// Build the basic environment variables for the child process based on the authenticated user and requested terminal type.
///
/// The returned environment variables are:
/// - `TERM`: set to the requested terminal type or default to `xterm-256
/// - `HOME`: set to the user's home directory
/// - `USER`: set to the user's name
/// - `LOGNAME`: set to the user's name
/// - `SHELL`: set to the user's shell
fn child_env(user: &uzers::User, term: Option<&str>) -> Vec<CString> {
    vec![
        cstring!("TERM=", term.unwrap_or("xterm-256color")).unwrap(),
        cstring!("HOME=", user.home_dir()).unwrap(),
        cstring!("USER=", user.name()).unwrap(),
        cstring!("LOGNAME=", user.name()).unwrap(),
        cstring!("SHELL=", user.shell()).unwrap(),
    ]
}
