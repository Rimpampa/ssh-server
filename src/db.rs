use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::OnceCell;

struct Entry {
    ip: IpAddr,
    user: OnceCell<String>,
    connected: bool,
}

impl Entry {
    fn user(&self) -> Option<&str> {
        self.user.get().map(String::as_str)
    }
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

    pub fn connected(&self, ip: IpAddr) -> anyhow::Result<()> {
        let mut lock = self.inner.lock().unwrap();
        match lock.iter().position(|e| e.ip == ip) {
            Some(pos) if lock[pos].connected => {
                anyhow::bail!("Rejecting new connection from {ip}: already connected");
            }
            Some(pos) => {
                lock[pos].connected = true;
                Ok(())
            }
            None => {
                lock.push(Entry {
                    ip,
                    user: OnceCell::new(),
                    connected: true,
                });
                Ok(())
            }
        }
    }

    pub fn authorized(&self, ip: IpAddr, user: &str) -> anyhow::Result<()> {
        let user = user.trim();
        if user == "root" {
            anyhow::bail!("root login is not allowed!")
        }

        let lock = self.inner.lock().unwrap();
        if let Some(pos) = lock.iter().position(|e| e.user() == Some(user)) {
            anyhow::bail!(
                "Rejecting new connection from {user}@{ip}: already logged-in from {}",
                lock[pos].ip
            );
        };
        let Some(pos) = lock.iter().position(|e| e.ip == ip) else {
            anyhow::bail!("*should be impossible to see this*")
        };
        lock[pos].user.set(user.to_string()).map_err(Into::into)
    }

    pub fn disconnected(&self, ip: IpAddr) {
        let mut lock = self.inner.lock().unwrap();
        let Some(pos) = lock.iter().position(|e| e.ip == ip) else {
            unreachable!()
        };
        lock[pos].connected = false;
    }

    pub fn user(&self, ip: IpAddr) -> Option<String> {
        let lock = self.inner.lock().unwrap();
        lock.iter()
            .find_map(|e| (e.ip == ip).then(|| e.user()).flatten())
            .map(|s| s.to_string())
    }
}
