//! Hand-written FFI bindings to libpam and a safe PAM session wrapper.
//!
//! Mirrors the style of `crypt.rs` — no proc-macro / bindgen, just
//! `extern "C"` declarations and a thin safe wrapper on top.
//!
//! Lifecycle performed by [`PamSession::open`]:
//!   `pam_start` → `pam_authenticate` → `pam_acct_mgmt` →
//!   `pam_setcred(ESTABLISH)` → `pam_open_session` → `pam_setcred(REINITIALIZE)`
//!
//! [`Drop`] runs:
//!   `pam_close_session` → `pam_setcred(DELETE)` → `pam_end`

#![allow(non_upper_case_globals)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

mod ffi {
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/pam_appl.rs"));
}

// ── Conversation callback ─────────────────────────────────────────────────────

struct Credentials {
    username: CString,
    password: CString,
}

/// PAM conversation function.
///
/// Responds with the pre-set password for `PAM_PROMPT_ECHO_OFF` prompts and
/// with the username for `PAM_PROMPT_ECHO_ON` prompts.
/// Response strings are allocated with `malloc`/`strdup` so that PAM can
/// `free()` them with its own allocator.
unsafe extern "C" fn conversation(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    let creds = &*(appdata_ptr as *const Credentials);

    let responses =
        malloc(num_msg as usize * std::mem::size_of::<PamResponse>()) as *mut PamResponse;
    if responses.is_null() {
        return 4; // PAM_BUF_ERR
    }

    for i in 0..num_msg as usize {
        let m = &**msg.add(i);
        let r = &mut *responses.add(i);
        r.resp_retcode = 0;
        r.resp = match m.msg_style {
            PAM_PROMPT_ECHO_OFF => strdup(creds.password.as_ptr()),
            PAM_PROMPT_ECHO_ON => strdup(creds.username.as_ptr()),
            _ => ptr::null_mut(),
        };
    }

    *resp = responses;
    PAM_SUCCESS
}

// ── PamSession ────────────────────────────────────────────────────────────────

/// An open PAM session for an authenticated user.
///
/// Created via [`PamSession::open`]. Dropping this value closes the session
/// and ends the PAM transaction.
pub struct PamSession {
    handle: *mut PamHandle,
    last_status: c_int,
    // Both fields below must outlive `handle`: Linux-PAM stores a pointer to
    // `_conv` internally, and `_conv.appdata_ptr` points into `_creds`.
    _conv: Box<PamConv>,
    _creds: Box<Credentials>,
}

// SAFETY: the PAM handle is owned exclusively by this struct; we never share
// it across threads and all access is through exclusive ownership.
unsafe impl Send for PamSession {}

impl PamSession {
    /// Authenticate `username`/`password` against the `"sshd"` PAM service
    /// and open a session.
    pub fn open(username: &str, password: &str) -> anyhow::Result<Self> {
        let service = CString::new("sshd")?;
        let user = CString::new(username)?;

        let creds = Box::new(Credentials {
            username: CString::new(username)?,
            password: CString::new(password)?,
        });

        // `conv.appdata_ptr` points into `creds`; both are moved into the
        // returned `PamSession` so they stay alive for the duration.
        let conv = Box::new(PamConv {
            conv: conversation,
            appdata_ptr: &*creds as *const Credentials as *mut c_void,
        });

        let mut handle: *mut PamHandle = ptr::null_mut();

        macro_rules! pam {
            ($call:expr, $msg:literal) => {{
                let rc = unsafe { $call };
                if rc != PAM_SUCCESS {
                    anyhow::bail!(concat!($msg, " failed (PAM error code {})"), rc);
                }
            }};
        }

        pam!(pam_start(service.as_ptr(), user.as_ptr(), &*conv, &mut handle), "pam_start");
        pam!(pam_authenticate(handle, 0), "pam_authenticate");
        pam!(pam_acct_mgmt(handle, 0), "pam_acct_mgmt");
        pam!(pam_setcred(handle, PAM_ESTABLISH_CRED), "pam_setcred(establish)");
        pam!(pam_open_session(handle, 0), "pam_open_session");
        pam!(pam_setcred(handle, PAM_REINITIALIZE_CRED), "pam_setcred(reinitialize)");

        Ok(Self {
            handle,
            last_status: PAM_SUCCESS,
            _conv: conv,
            _creds: creds,
        })
    }
}

impl Drop for PamSession {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        // SAFETY: handle is valid and we have exclusive ownership.
        unsafe {
            pam_close_session(self.handle, 0);
            pam_setcred(self.handle, PAM_DELETE_CRED);
            pam_end(self.handle, self.last_status);
        }
        self.handle = ptr::null_mut();
    }
}
