use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use anyhow::Context;

use crate::crypt;

struct Entry {
    addr: Option<SocketAddr>,
    user: uzers::User,
}

#[derive(Clone, Default)]
pub struct Database {
    // sequential search is suboptimal but this server shouldn't ever expirience more than 20 users
    inner: Arc<Mutex<Vec<Entry>>>,
}

impl Database {
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new user in the OS and set its password in /etc/shadow
    async fn create(user: &str, password: &str) -> anyhow::Result<uzers::User> {
        if !Command::new("useradd")
            .arg("-m")
            .arg(user)
            .status()
            .await?
            .success()
        {
            anyhow::bail!("useradd failed")
        };

        let salt = crypt::gensalt(None, 0, None).with_context(|| "Salt generation failed")?;
        let password = CString::new(password)?;
        let password = crypt::crypt(&password, &salt).with_context(|| "Password hashing failed")?;
        let password = password.into_string().with_context(|| "Password conversion failed")?;
        let password = format!("{user}:{password}:");

        let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
        let shadow = shadow.replace(&format!("{user}:!:"), &password);
        tokio::fs::write("/etc/shadow", shadow).await?;

        match uzers::get_user_by_name(user) {
            Some(user) => Ok(user),
            None => anyhow::bail!("* impossible *"),
        }
    }

    /// Verify that the given existing user as the provided password in /etc/shadow
    async fn verify(user: uzers::User, password: &str) -> anyhow::Result<uzers::User> {
        let pat = format!("{}:", user.name().to_str().unwrap());
        let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
        let line = shadow.lines().find(|l| l.starts_with(&pat)).with_context(|| "User not in /etc/shadow")?;
        let enc = line.split(':').nth(1).with_context(|| "Malformed /etc/shadow")?;
        let enc = CString::new(enc)?;
        let password = CString::new(password)?;
        anyhow::ensure!(crypt::verify(&password, &enc), "Wrong password");
        Ok(user)
    }

    pub async fn authorize(
        &self,
        addr: SocketAddr,
        user: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        let user = user.trim();
        if user == "root" {
            anyhow::bail!("root login is not allowed!")
        }

        let user = match uzers::get_user_by_name(user) {
            None => Self::create(user, password).await?,
            Some(user) => Self::verify(user, password).await?,
        };

        let mut lock = self.inner.lock().unwrap();
        match lock.iter_mut().find(|e| e.user.name() == user.name()) {
            None => lock.push(Entry {
                addr: Some(addr),
                user,
            }),
            Some(entry) => {
                if let Some(addr) = entry.addr {
                    anyhow::bail!(
                        "Rejecting new connection from '{}': already logged-in from {addr}",
                        user.name().display()
                    );
                }
                entry.addr = Some(addr)
            }
        }
        Ok(())
    }

    pub fn disconnected(&self, addr: SocketAddr) {
        let mut lock = self.inner.lock().unwrap();
        if let Some(pos) = lock.iter().position(|e| e.addr == Some(addr)) {
            lock[pos].addr = None;
        };
    }

    pub fn user(&self, addr: SocketAddr) -> Option<uzers::User> {
        let lock = self.inner.lock().unwrap();
        lock.iter()
            .position(|e| e.addr == Some(addr))
            .map(|pos| lock[pos].user.clone())
    }
}
