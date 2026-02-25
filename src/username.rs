use std::cell::OnceCell;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Username {
    inner: Arc<Mutex<OnceCell<Box<str>>>>,
}

impl Username {
    pub fn get(&self) -> Option<Box<str>> {
        self.inner.lock().unwrap().get().cloned()
    }

    pub fn set(&self, user: impl Into<Box<str>>) -> anyhow::Result<()> {
        let user = user.into();
        let lock = self.inner.lock().unwrap();
        match lock.get() {
            Some(existing) => anyhow::ensure!(
                *existing == user,
                "Username already set to {existing} (new value {user})"
            ),
            None => lock.set(user).unwrap(),
        }
        Ok(())
    }
}
