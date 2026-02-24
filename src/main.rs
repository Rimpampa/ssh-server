use std::collections::{HashSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};

use russh::server::{Auth, Handle, Session, Msg, Handler};
use russh::{CryptoVec, ChannelId, Channel};
use russh::keys::PrivateKey;
use russh::keys::ssh_key::rand_core::OsRng;

use tokio::net::TcpListener;
use tokio::process::{Command, ChildStdin};
use tokio::io::BufReader;
use tokio::sync::Mutex as TokioMutex;

use uzers::os::unix::UserExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = russh::server::Config::default();
    config.keys = vec![
        PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519)?,
    ];
    config.auth_rejection_time = std::time::Duration::from_secs(0);
    config.auth_rejection_time_initial = Some(std::time::Duration::from_secs(0));
    config.inactivity_timeout = Some(std::time::Duration::from_secs(3600));

    let config = Arc::new(config);

    let listener = TcpListener::bind(("0.0.0.0", 2222)).await?;
    println!("Listening on 0.0.0.0:2222");

    let set = Arc::new(StdMutex::new(HashSet::<IpAddr>::new()));
    loop {
        let (stream, addr) = listener.accept().await?;
        let config = config.clone();

        if set.lock().unwrap().contains(&addr.ip()) {
            eprintln!("Rejecting new connection from {}: already connected", addr.ip());
            continue;
        }

        let set = set.clone();
        tokio::spawn(async move {
            if let Err(e) = russh::server::run_stream(config, stream, Connection::default()).await {
                eprintln!("Connection error: {:?}", e);
            }
            set.lock().unwrap().remove(&addr.ip());
        });
    }
}

#[derive(Clone, Default)]
struct Connection {
    username: Option<Box<str>>,
    stdin: Arc<TokioMutex<OnceCell<ChildStdin>>>,
}

impl Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.username = Some(user.into());
        if let None = uzers::get_user_by_name(user) {
            let status = Command::new("useradd").arg("-m").arg(user).status().await?;
            if !status.success() {
                anyhow::bail!("useradd failed");
            }
        }
        Ok(Auth::Accept)
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        let Some(user) = self.username.as_deref().and_then(|user| uzers::get_user_by_name(user)) else { return Ok(false) };
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

        self.stdin.lock().await.set(stdin).map_err(|_| anyhow::anyhow!("Already initialized TODO"))?;

        forward(channel.id(), session.handle(), stdout);
        forward(channel.id(), session.handle(), stderr);

        session.channel_success(channel.id())?;
        Ok(true)
    }

    async fn data(&mut self, _channel: russh::ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        let mut stdin = self.stdin.lock().await;
        let Some(stdin) = stdin.get_mut() else { return Ok(()) };
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
