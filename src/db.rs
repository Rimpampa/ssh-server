use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use sha2::{Digest, Sha256};

use base64::prelude::*;

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

    /// Hashes the password as it would be done by the `crypt` command
    fn crypt(password: &str) -> String {
        //↓ 5 is the code for SHA256
        format!("$5$${}", BASE64_STANDARD.encode(Sha256::digest(password)))
    }

    /// Add the user to the OS and set its password in /etc/shadow
    async fn add(user: &str, password: &str) -> anyhow::Result<()> {
        if !Command::new("useradd")
            .arg("-m")
            .arg(user)
            .status()
            .await?
            .success()
        {
            anyhow::bail!("useradd failed")
        };

        let password = Self::crypt(password);

        let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
        let shadow = shadow.replace(&format!("{user}:!:"), &format!("{user}:{password}:"));
        tokio::fs::write("/etc/shadow", shadow).await?;

        Ok(())
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

        let Some(uzer) = uzers::get_user_by_name(user) else {
            return Self::add(user, password).await;
        };

        let password = format!("{user}:{}:", Self::crypt(password));
        let shadow = tokio::fs::read_to_string("/etc/shadow").await?;
        if !shadow.lines().any(|line| line.starts_with(&password)) {
            anyhow::bail!("Wrong password!")
        }

        let mut lock = self.inner.lock().unwrap();
        match lock.iter().position(|e| e.user.name() == uzer.name()) {
            None => lock.push(Entry {
                addr: Some(addr),
                user: uzer,
            }),
            Some(pos) => {
                if let Some(addr) = lock[pos].addr {
                    anyhow::bail!(
                        "Rejecting new connection from {user}: already logged-in from {addr}",
                    );
                }
                lock[pos].addr = Some(addr)
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
