mod crypt;
mod pam_auth;
mod session;

use anyhow::Context;
use tokio::process::Child;

use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use uzers::os::unix::UserExt;

use log::{debug, error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .format_timestamp_millis()
        .init();

    info!("SSH Server starting");

    // Ensure we can change uid/gid — this server must run as root to start sessions as other users
    if uzers::get_effective_uid() != 0 {
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

    let session = session::Session::new();
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("New connection from {addr}");

        let config = config.clone();
        let session = session.start(addr);
        tokio::spawn(async move {
            debug!("Starting SSH session handler for {addr}");
            let conn = Connection::new(session);
            let Ok(stream) = russh::server::run_stream(config, stream, conn).await else {
                return;
            };
            let res = stream.await;
            info!("[{addr}] SSH session ended with: {res:?}");
        });
    }
}

struct Connection {
    session: session::Session,
    term: Option<String>,
    pty: Option<pty_process::OwnedWritePty>,
    read: Option<pty_process::OwnedReadPty>,
    child: Option<Child>,
}

impl Connection {
    fn new(session: session::Session) -> Self {
        Self {
            session,
            term: None,
            pty: None,
            read: None,
            child: None,
        }
    }
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if let Err(e) = self.session.authorize(user, password).await {
            warn!("[{}] Authentication failed with: {e}", self.session.log());
            return Ok(Auth::reject());
        };

        let (pty, pts) = pty_process::open()?;
        let (read, write) = pty.into_split();
        self.pty = Some(write);
        self.read = Some(read);

        let user = self.session.user();
        let command = pty_process::Command::new(user.shell())
            .arg("-i")
            .uid(user.uid())
            .gid(user.primary_group_id())
            .current_dir(user.home_dir())
            .env("TERM", self.term.as_deref().unwrap_or("xterm-256color"))
            .env("HOME", user.home_dir())
            .env("USER", user.name())
            .env("LOGNAME", user.name())
            .env("SHELL", user.shell());
        self.child = Some(command.spawn(pts)?);

        info!("[{}] Authenticated", self.session.log());
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
        let log = self.session.log();
        info!("[{log}] PTY request: term={term}, cols={col_w}, rows={row_h}");
        self.term = Some(term.to_string());
        match &mut self.pty {
            Some(pty) => {
                pty.resize(pty_process::Size::new_with_pixel(
                    row_h as u16,
                    col_w as u16,
                    pix_w as u16,
                    pix_h as u16,
                ))?;
                session.channel_success(channel)?;
            }
            None => {
                warn!("[{log}] PTY requested but no master fd available");
                session.channel_failure(channel)?;
            }
        }
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
        let log = self.session.log();
        info!("[{log}] Window change request: cols={col_w}, rows={row_h}");
        match &mut self.pty {
            Some(pty) => {
                pty.resize(pty_process::Size::new_with_pixel(
                    row_h as u16,
                    col_w as u16,
                    pix_w as u16,
                    pix_h as u16,
                ))?;
                session.channel_success(channel)?;
            }
            None => {
                warn!("[{log}] Window change requested but no master fd available");
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
        let id = channel.id();

        let log = self.session.log();
        info!("[{log}] Channel {id} open session request");

        let handle = session.handle();
        let read = self
            .read
            .take()
            .with_context(|| "Missing read half of PTY")?;
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(1024, read);
            while let Ok(buf @ [_, ..]) = reader.fill_buf().await
                && let Ok(_) = handle.data(id, CryptoVec::from(buf)).await
            {
                let len = buf.len();
                reader.consume(len);
            }
        });

        session.channel_success(id)?;
        info!("[{log}] Channel {id} session opened successfully");

        let handle = session.handle();
        let log = log.to_string();
        let mut child = self.child.take().with_context(|| "Missing child process handle")?;
        tokio::task::spawn(async move {
            let _ = child.wait().await;
            info!("[{log}] Shell process ended, disconnetting...");
            let _ = handle.close(id).await;
            let _ = handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "User requested exit".into(),
                    "".into(),
                )
                .await;
        });

        Ok(true)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(pty) = self.pty.as_mut() else {
            warn!(
                "[{}] Data received but no PTY available",
                self.session.log()
            );
            return Ok(());
        };
        pty.write_all(data).await?;
        pty.flush().await?;
        Ok(())
    }
}
