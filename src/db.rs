use std::net::{ SocketAddr};
use std::sync::{Arc, Mutex};


struct Entry {
    addr: Option<SocketAddr>,
    user: String,
    pswd: String,
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

    pub fn authorized(&self, addr: SocketAddr, user: &str, password: &str) -> anyhow::Result<()> {
        let user = user.trim();
        if user == "root" {
            anyhow::bail!("root login is not allowed!")
        }

        let mut lock = self.inner.lock().unwrap();
        match lock.iter().position(|e| &e.user == user) {
            None => {
                lock.push(Entry {
                    addr: Some(addr),
                    user: user.to_string(),
                    pswd: password.to_string(),
                });
            }
            Some(pos) => {
                if let Some(addr) = lock[pos].addr {
                    anyhow::bail!(
                        "Rejecting new connection from {user}: already logged-in from {addr}",
                    );
                }
                if &lock[pos].pswd != password {
                    anyhow::bail!(
                        "Rejecting new connection from {user}: worng credentials",
                    );
                }
                lock[pos].addr = Some(addr);
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

    pub fn user(&self, addr: SocketAddr) -> Option<String> {
        let lock = self.inner.lock().unwrap();
        lock.iter()
            .position(|e| e.addr == Some(addr))
            .map(|pos| lock[pos].user.clone())
    }
}
