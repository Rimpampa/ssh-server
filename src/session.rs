use std::collections::HashMap;
use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::process::Command;

use anyhow::Context;

use crate::crypt;
use crate::pam_auth::PamSession;

pub type Database = HashMap<String, Option<SocketAddr>>;

pub struct Session {
    db: Arc<Mutex<Database>>,
    addr: SocketAddr,
    user: uzers::User,
    log: String,
    /// Holds the open PAM session for the authenticated user.
    /// `None` before authentication; `Some` afterwards.
    pam_session: Option<PamSession>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            db: Arc::new(Mutex::new(HashMap::new())),
            addr: ([0; 4], 0).into(),
            user: uzers::User::new(0, "root", 0),
            log: String::new(),
            pam_session: None,
        }
    }

    pub fn start(&self, addr: SocketAddr) -> Self {
        Self {
            db: self.db.clone(),
            addr,
            user: self.user.clone(),
            log: format!("???@{addr}"),
            pam_session: None,
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

        // Ensure the OS user exists before handing off to PAM.
        // For new users we create the account and pre-set the password so that
        // the standard pam_unix module can authenticate them immediately after.
        self.user = match uzers::get_user_by_name(name) {
            None => {
                create(name, password).await?;
                uzers::get_user_by_name(name)
                    .with_context(|| "create function somehow failed without error")?
            }
            Some(user) => user,
        };

        // Authenticate and open a PAM session. This replaces the previous
        // direct /etc/shadow verification and gives the PAM stack (pam_unix,
        // pam_limits, pam_env, …) a chance to run all of its modules.
        // Dropping the value later closes the session.
        let pam = tokio::task::spawn_blocking({
            let name = name.to_owned();
            let password = password.to_owned();
            move || PamSession::open(&name, &password)
        })
        .await
        .with_context(|| "PAM task panicked")??;

        self.pam_session = Some(pam);
        self.log = format!("{name}@{}", self.addr);

        let mut lock = self.db.lock().unwrap();
        match lock.entry(name.into()).or_default() {
            Some(addr) => anyhow::bail!("Already logged-in from {addr}"),
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

/// Create a new user in the OS and set its password in /etc/shadow so that
/// pam_unix can authenticate the user immediately afterwards.
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

