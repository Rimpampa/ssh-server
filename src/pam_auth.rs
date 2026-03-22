//! PAM authentication and session management.
//!
//! A [`PamSession`] authenticates a user via the system PAM stack and keeps the
//! PAM session open for the lifetime of the value. Dropping it calls
//! `pam_close_session` + `pam_end` automatically (via `pam::Client`'s own Drop
//! with `close_on_drop = true`).

use pam::{Client, PasswordConv};

/// An open PAM session for an authenticated user.
///
/// Constructed via [`PamSession::open`]. The underlying PAM session is closed
/// when this value is dropped.
pub struct PamSession(Client<'static, PasswordConv>);

// SAFETY: `Client` contains a raw `*mut PamHandle` which is `!Send` by default.
// We own the handle exclusively — it is never shared between threads — and all
// PAM operations are serialised through `&mut self`. The underlying C PAM
// library documents that a single PAM transaction must not be accessed
// concurrently, a constraint we satisfy via exclusive ownership.
unsafe impl Send for PamSession {}

impl PamSession {
    /// Authenticate `username` / `password` against the `"sshd"` PAM service
    /// and open a session for the user.
    ///
    /// Returns an error if authentication or session opening fails.
    pub fn open(username: &str, password: &str) -> anyhow::Result<Self> {
        let mut client = Client::with_password("sshd")
            .map_err(|e| anyhow::anyhow!("PAM init failed: {e:?}"))?;

        client.conversation_mut().set_credentials(username, password);

        client
            .authenticate()
            .map_err(|e| anyhow::anyhow!("PAM authentication failed: {e:?}"))?;

        client
            .open_session()
            .map_err(|e| anyhow::anyhow!("PAM session open failed: {e:?}"))?;

        Ok(Self(client))
    }
}
