// pam_limits    | Applies resource limits (ulimits) from /etc/security/limits.conf
// pam_mkhomedir | Creates home directory on first login if it doesn't exist
// pam_unix      | Core Unix auth — checks passwords against /etc/shadow
// pam_localuser | Succeeds only if user exists in local /etc/passwd
// pam_exec      | Runs an arbitrary external command during auth

#![allow(non_upper_case_globals)]

use std::ffi::*;
use std::ptr;

use pam_sys::*;

type Result<T> = std::result::Result<T, String>;

/// An open PAM session for an authenticated user.
///
/// Created via [`PamSession::open`]. Dropping this value closes the session
/// and ends the PAM transaction.
pub struct Session {
    handle: *mut pam_handle_t,
    status: u32,
    _psw: Box<CStr>,
    _conv: Box<pam_conv>,
}

// SAFETY: the PAM handle is owned exclusively by this struct; we never share
// it across threads and all access is through exclusive ownership.
unsafe impl Send for Session {}

macro_rules! pam {
    ($self:expr, $fn:expr, $($param:expr),* $(,)?) => {{
        let res = $fn($self.handle, $($param),*);
        $self.result(stringify!($fn), res)
    }}
}

impl Session {
    fn status_str(&self) -> &'static str {
        // SAFETY: todo
        let ptr = unsafe { pam_strerror(self.handle, self.status.cast_signed()) };
        if ptr.is_null() {
            return "* null *";
        }
        // SAFETY: if the pointer returned by pam_strerror is not null then it's
        // guaranteed to point to a null-terminated byte string
        let str = unsafe { CStr::from_ptr(ptr) };

        str.to_str().unwrap_or("* invalid *")
    }

    fn result(&mut self, step: &str, result: c_int) -> Result<()> {
        self.status = result.cast_unsigned();
        match self.status {
            PAM_SUCCESS => Ok(()),
            e => Err(format!("{step}:{e}: {}", self.status_str())),
        }
    }

    /// Starts a PAM session with the "ssh-server" service
    fn start(&mut self, user: &str) -> Result<()> {
        let user = CString::new(user).unwrap();
        // SAFETY:
        // - `service_name` is a null-terminated byte string
        // - `username` is a null-terminated byte string
        let res = unsafe {
            pam_start(
                c"ssh-server".as_ptr(),
                user.as_ptr(),
                &*self._conv,
                &mut self.handle,
            )
        };
        self.result("pam_start", res)
    }

    /// Sets a PAM item that is expected to be a C string.
    ///
    /// # Safety
    ///
    /// The selected `item` must be one that Linux-PAM expects to be a C string (e.g. `PAM_AUTHTOK` or `PAM_RHOST`).
    unsafe fn set_cstr_item(&mut self, item: u32, value: impl Into<Vec<u8>>) -> Result<()> {
        let str = CString::new(value).unwrap();
        // SAFETY: todo
        unsafe {
            pam!(
                self,
                pam_set_item,
                item.cast_signed(),
                str.as_ptr() as *const _
            )
        }
    }

    /// Authenticate `username`/`password` against the `"ssh-server"` PAM service
    /// and open a session.
    ///
    /// Runs `pam_start` → `pam_authenticate` → `pam_acct_mgmt` →
    /// `pam_setcred(ESTABLISH)` → `pam_open_session`.
    /// Dropping the returned value closes the session via `pam_close_session`,
    /// `pam_setcred(DELETE)`, and `pam_end`.
    pub fn open(username: &str, password: &str, host: &str) -> Result<Self> {
        let _psw = CString::new(password).unwrap().into_boxed_c_str();
        let mut session = Self {
            handle: std::ptr::null_mut(),
            status: PAM_SUCCESS,
            _conv: Box::new(pam_conv {
                conv: Some(conv),
                appdata_ptr: _psw.as_ptr() as _,
            }),
            _psw,
        };
        session.start(username)?;

        unsafe extern "C" fn nodelay(_: c_int, _: c_uint, _: *const c_void) {}
        // SAFETY: todo
        unsafe {
            pam!(
                session,
                pam_set_item,
                PAM_FAIL_DELAY.cast_signed(),
                nodelay as *const _
            )
        }?;
        // SAFETY: todo
        unsafe { session.set_cstr_item(PAM_RUSER, username) }?;
        // SAFETY: todo
        unsafe { session.set_cstr_item(PAM_RHOST, host) }?;
        // SAFETY: todo
        unsafe { pam!(session, pam_authenticate, 0) }?;
        // SAFETY: todo
        unsafe { pam!(session, pam_acct_mgmt, 0) }?;
        // SAFETY: todo
        unsafe { pam!(session, pam_setcred, PAM_ESTABLISH_CRED as c_int) }?;
        // SAFETY: todo
        unsafe { pam!(session, pam_open_session, 0) }?;
        Ok(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        // SAFETY: handle is valid and we have exclusive ownership.
        unsafe {
            pam_close_session(self.handle, 0);
            pam_setcred(self.handle, PAM_DELETE_CRED as c_int);
            pam_end(self.handle, self.status.cast_signed());
        }
        self.handle = ptr::null_mut();
    }
}

/// PAM conversation function.
///
/// Responds to `PAM_PROMPT_ECHO_OFF` prompts with the password passed via the `pam_conv::appdata_ptr` parameter.
///
/// Response buffer and strings are allocated with `libc::malloc` so that the PAM
/// library can `free()` them with its own allocator.
///
/// NOTE: I've assumed that the default allocator used by `Box` relies on libc.
unsafe extern "C" fn conv(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int {
    let Ok(num_msg) = num_msg.try_into() else {
        return PAM_CONV_ERR as _;
    };

    // SAFETY: this function is only called in `PamSession::open` which always
    // sets the `appdata_ptr` to a pointer to a `CStr`
    let psw = unsafe { CStr::from_ptr(appdata_ptr as _) };

    // SAFETY: in theory in `msg` we have exclusive access to an array
    // of references to initialized `pam_message` items
    let msg = unsafe { std::slice::from_raw_parts_mut(msg as *mut &pam_message, num_msg) };

    // NOTE: I assume the default allocator used by Box relies on libc
    let mut responses = Box::new_uninit_slice(num_msg);

    for (r, m) in responses.iter_mut().zip(msg) {
        let resp = match m.msg_style.cast_unsigned() {
            // NOTE: I assume the default allocator used by Box relies on libc
            PAM_PROMPT_ECHO_OFF => psw.to_owned().into_raw(),
            _ => std::ptr::null_mut(),
        };
        r.write(pam_response {
            resp,
            resp_retcode: 0,
        });
    }
    // SAFETY: all the elements in the responses slice are initialized
    let responses = unsafe { responses.assume_init() };
    // SAFETY: the PAM library guarantees that resp is a pointer to a pam_response
    unsafe { *resp = Box::into_raw(responses) as _ };
    PAM_SUCCESS as _
}
