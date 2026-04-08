use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub type Database = HashMap<String, Option<SocketAddr>>;

pub struct Session {
    db: Arc<Mutex<Database>>,
    addr: SocketAddr,
    user: String,
    log: String,
}

impl Session {
    pub fn new() -> Self {
        Self {
            db: Arc::new(Mutex::new(HashMap::new())),
            addr: ([0; 4], 0).into(),
            user: String::new(),
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

    pub async fn authorize(&mut self, name: &str) -> anyhow::Result<()> {
        let name = name.trim();
        if name == "root" {
            anyhow::bail!("root login is not allowed")
        }

        self.user = name.into();
        self.log = format!("{name}@{}", self.addr);

        let mut lock = self.db.lock().unwrap();
        match lock.entry(name.into()).or_default() {
            Some(addr) => anyhow::bail!("Already logged-in from {addr}"),
            entry @ None => *entry = Some(self.addr),
        }
        Ok(())
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn log(&self) -> &str {
        &self.log
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut lock = self.db.lock().unwrap();
        if let Some(addr) = lock.get_mut(self.user()) {
            *addr = None;
        }
    }
}
