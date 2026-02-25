use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Database {
    inner: Arc<Mutex<HashMap<IpAddr, Entry>>>,
}

impl Database {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn connected(&self, ip: IpAddr) -> anyhow::Result<crate::Username> {
        let mut lock = self.inner.lock().unwrap();
        let entry = lock.entry(ip).or_insert_with(Default::default);
        anyhow::ensure!(
            !entry.connected,
            "Rejecting new connection from {ip}: already connected"
        );
        entry.connected = true;
        Ok(entry.username.clone())
    }

    pub fn disconnected(&self, ip: IpAddr) {
        self.inner.lock().unwrap().get_mut(&ip).unwrap().connected = false;
    }
}

#[derive(Clone, Default)]
struct Entry {
    connected: bool,
    username: crate::Username,
}
