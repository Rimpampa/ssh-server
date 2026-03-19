mod db;
use db::Database;

mod crypt;

use anyhow::Context;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::server::{Auth, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
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

    let db = Database::new();
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("New connection from {addr}");

        let config = config.clone();
        let db = db.clone();
        tokio::spawn(async move {
            debug!("Starting SSH session handler for {addr}");
            let conn = Connection::new(db.clone(), addr);
            let session = russh::server::run_stream(config, stream, conn).await?;
            if let Err(e) = session.await {
                debug!("SSH session ended with error {e:?}");
            }
            info!("SSH session ended for {addr}");
            db.disconnected(addr);
            info!("Disconnected {addr}");
            Result::<(), anyhow::Error>::Ok(())
        });
    }
}

struct Connection {
    db: Database,
    addr: SocketAddr,
    term: Option<String>,
    /// Child's stdin as an async file
    pty: Option<pty_process::OwnedWritePty>,
}

impl Connection {
    fn new(db: Database, addr: SocketAddr) -> Self {
        Self {
            db,
            addr,
            term: None,
            pty: None,
        }
    }
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!("Authentication attempt for '{user}'");

        if let Err(e) = self.db.authorize(self.addr, user, password).await {
            warn!("Authentication failed for '{user}': {e}");
            return Ok(Auth::reject());
        };

        info!("Authentication accepted for '{user}'");
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
                warn!("PTY requested but no master fd available for channel {channel}",);
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
        info!("Window change request for channel {channel}: cols={col_w}, rows={row_h}",);
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
        let Some(user) = self.db.user(self.addr) else {
            warn!("Channel open session failed: no username set for channel {channel_id}",);
            return Ok(false);
        };
        let name = user.name();
        info!("{name:?} - Channel {channel_id} open session request");

        let (pty, pts) = pty_process::open()?;
        let (read, write) = pty.into_split();
        self.pty = Some(write);

        let mut child = pty_process::Command::new(user.shell())
            .arg("-i")
            .uid(user.uid())
            .gid(user.primary_group_id())
            .current_dir(user.home_dir())
            .env("TERM", self.term.as_deref().unwrap_or("xterm-256color"))
            .env("HOME", user.home_dir())
            .env("USER", &name)
            .env("LOGNAME", &name)
            .env("SHELL", user.shell())
            .spawn(pts)?;

        forward(channel_id, session.handle(), read);

        session.channel_success(channel_id)?;
        info!("{name:?} - Channel {channel_id} session opened successfully");

        let name = name.to_os_string();
        tokio::task::spawn(async move {
            let _ = child.wait().await;
            info!("{name:?} - Shell process ended");
        });

        Ok(true)
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(pty) = self.pty.as_mut() else {
            warn!("Data received but no PTY available for channel {channel}",);
            return Ok(());
        };
        pty.write_all(data).await?;
        pty.flush().await?;
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
        info!("Child process ended, closing channel {id} and disconnecting...");
        let _ = handle.close(id);
        let _ = handle.disconnect(
            russh::Disconnect::ByApplication,
            "User requested exit".into(),
            "".into(),
        );
    });
}
