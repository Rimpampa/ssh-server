//! Raw bindings to libcrypt. unsafe rust required
#![allow(non_upper_case_globals)]

use std::ffi::*;
use std::mem::MaybeUninit;
use std::ptr::null;

mod ffi {
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/crypt.rs"));
}

// pub fn preferred_method() -> Option<&'static CStr> {
//     // SAFETY: this function is safe.
//     let ptr = unsafe { ffi::crypt_preferred_method() };
//     if ptr.is_null() {
//         return None;
//     }
//     // SAFETY: it's a valid pointer to a null-terminated string.
//     Some(unsafe { CStr::from_ptr(ptr) })
// }

pub fn gensalt(prefix: Option<&CStr>, count: c_ulong, random: Option<&[u8]>) -> Option<CString> {
    let buffer = [MaybeUninit::<u8>::uninit(); ffi::CRYPT_GENSALT_OUTPUT_SIZE as usize];
    // SAFETY:
    // - `prefix` is either null or a valid pointer to a null-terminated string;
    // - `random` is either null or a valid pointer to a byte array of the specified length;
    // - `buffer` is a valid pointer to a writable buffer of at least `CRYPT_GENSALT_OUTPUT_SIZE` bytes.
    let ptr = unsafe {
        ffi::crypt_gensalt_rn(
            prefix.map_or(null(), |s| s.as_ptr()),
            count,
            random.map_or(null(), |r| r.as_ptr() as *const i8),
            random.map_or(0, |r| r.len() as _),
            buffer.as_ptr() as *mut i8,
            buffer.len() as _,
        )
    };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: it's a valid pointer to a null-terminated string.
    Some(unsafe { CStr::from_ptr(ptr) }.into())
}

pub fn crypt(password: &CStr, salt: &CStr) -> Option<CString> {
    let mut data = MaybeUninit::zeroed();
    // SAFETY: both `password` and `salt` are valid pointers to null-terminated strings.
    let ptr = unsafe { ffi::crypt_r(password.as_ptr(), salt.as_ptr(), data.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` is assured to be non-null and (in theory) points somewhere in `data`.
    if unsafe { ptr.read() } == b'*' as i8 {
        return None;
    }
    // SAFETY: it's a valid pointer to a null-terminated string
    Some(unsafe { CStr::from_ptr(ptr) }.into())
}

pub fn verify(password: &CStr, encrypted: &CStr) -> bool {
    crypt(password, encrypted).as_deref() == Some(encrypted)
}
