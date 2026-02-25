mod username;
use anyhow::Context;
use username::Username;

mod db;
use db::Database;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;

use russh::keys::PrivateKey;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::server::{Auth, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};

use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::process::{ChildStdin, Command};
use tokio::sync::Mutex;

use uzers::os::unix::UserExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Arc::new(russh::server::Config {
        keys: vec![PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519)?],
        auth_rejection_time: Duration::from_secs(0),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });

    let listener = TcpListener::bind(("0.0.0.0", 2222)).await?;
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
    // here a tokio mutex is needed because the lock to child stdin needs to be held
    // across await points, and the standard mutex doesn't support that (!Send)
    stdin: Arc<Mutex<OnceCell<ChildStdin>>>,
}

impl Connection {
    fn new(username: Username) -> Self {
        Self {
            username,
            stdin: Default::default(),
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

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self
            .username
            .get()
            .as_deref()
            .and_then(|user| uzers::get_user_by_name(user))
        else {
            return Ok(false);
        };
        let home = user.home_dir();

        let mut child = Command::new("/bin/sh")
            .arg("-i")
            .current_dir(&home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let stdin = child.stdin.take().unwrap();

        self.stdin
            .lock()
            .await
            .set(stdin)
            .map_err(|_| anyhow::anyhow!("Already initialized TODO"))?;

        forward(channel.id(), session.handle(), stdout);
        forward(channel.id(), session.handle(), stderr);

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
        let Some(stdin) = stdin.get_mut() else {
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
