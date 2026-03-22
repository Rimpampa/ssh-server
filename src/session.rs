use std::collections::HashMap;
use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use anyhow::Context;

use crate::crypt;

pub type Database = HashMap<String, Option<SocketAddr>>;

#[derive(Clone)]
pub struct Session {
    db: Arc<Mutex<Database>>,
    addr: SocketAddr,
    user: uzers::User,
    log: String,
}

impl Session {
    pub fn new() -> Self {
        Self {
            db: Arc::new(Mutex::new(HashMap::new())),
            addr: ([0; 4], 0).into(),
            user: uzers::User::new(0, "root", 0),
            log: String::new(),
        }
    }

    pub fn start(&self, addr: SocketAddr) -> Self {
        Self {
            db: self.db.clone(),
            addr,
            user: self.user.clone(),
            log: format!("???@{addr}"),
        }
    }

    pub async fn authorize(
        &mut self,
        name: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        let name = name.trim();
        if name == "root" {
            anyhow::bail!("root login is not allowed")
        }

        self.user = match uzers::get_user_by_name(name) {
            None => {
                create(name, password).await?;
                uzers::get_user_by_name(name).with_context(|| "create function somehow failed without error")?
            }
            Some(user) => {
                verify(name, password).await?;
                user
            }
        };
        self.log = format!("{name}@{}", self.addr);

        let mut lock = self.db.lock().unwrap();
        match lock.entry(name.into()).or_default() {
            Some(addr) => anyhow::bail!(
                "Already logged-in from {addr}",
            ),
            entry @ None => *entry = Some(self.addr),
        }
        Ok(())
    }

    pub fn user(&self) -> &uzers::User {
        &self.user
    }

    pub fn name(&self) -> &str {
        self.user.name().to_str().unwrap_or("") // <-- should be unreachable
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn log(&self) -> &str {
        &self.log
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut lock = self.db.lock().unwrap();
        if let Some(addr) = lock.get_mut(self.name()) {
            *addr = None;
        }
    }
}

/// Create a new user in the OS and set its password in /etc/shadow
async fn create(name: &str, password: &str) -> anyhow::Result<()> {
    let child = Command::new("useradd").arg("-m").arg(name).status().await?;
    if !child.success() {
        anyhow::bail!("useradd failed")
    };

    let salt = crypt::gensalt(None, 0, None).with_context(|| "Salt generation failed")?;
    let password = CString::new(password)?;
    let password = crypt::crypt(&password, &salt).with_context(|| "Password hashing failed")?;
    let password = password
        .into_string()
        .with_context(|| "Password conversion failed")?;
    let password = format!("{name}:{password}:");

    let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
    let shadow = shadow.replace(&format!("{name}:!:"), &password);
    tokio::fs::write("/etc/shadow", shadow).await?;
    Ok(())
}

/// Verify that the given existing user as the provided password in /etc/shadow
async fn verify(name: &str, password: &str) -> anyhow::Result<()> {
    let pat = format!("{name}:");
    let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
    let line = shadow
        .lines()
        .find(|l| l.starts_with(&pat))
        .with_context(|| "User not in /etc/shadow")?;
    let enc = line
        .split(':')
        .nth(1)
        .with_context(|| "Malformed /etc/shadow")?;
    let enc = CString::new(enc)?;
    let password = CString::new(password)?;
    anyhow::ensure!(crypt::verify(&password, &enc), "Wrong password");
    Ok(())
}
