use std::sync::Mutex;

use libc::{c_char, DEAD_PROCESS, USER_PROCESS};

// setutxent/pututxline/endutxent share global file state in glibc — serialize all access.
static UTMP_LOCK: Mutex<()> = Mutex::new(());

/// Write a USER_PROCESS utmp entry so `who` shows the logged-in user.
pub fn write_login(username: &str, pid: u32, line: &str, host: &str) {
    let _guard = UTMP_LOCK.lock().unwrap();
    unsafe {
        let mut entry: libc::utmpx = std::mem::zeroed();
        entry.ut_type = USER_PROCESS;
        entry.ut_pid = pid as libc::pid_t;
        copy_str(&mut entry.ut_line, line);
        copy_str(&mut entry.ut_id, &id_from_line(line));
        copy_str(&mut entry.ut_user, username);
        copy_str(&mut entry.ut_host, host);
        set_time(&mut entry);

        libc::setutxent();
        libc::pututxline(&entry);
        libc::endutxent();
    }
}

/// Write a DEAD_PROCESS utmp entry to remove the user from `who` on logout.
pub fn write_logout(line: &str) {
    let _guard = UTMP_LOCK.lock().unwrap();
    unsafe {
        let mut entry: libc::utmpx = std::mem::zeroed();
        entry.ut_type = DEAD_PROCESS;
        copy_str(&mut entry.ut_line, line);
        copy_str(&mut entry.ut_id, &id_from_line(line));
        set_time(&mut entry);

        libc::setutxent();
        libc::pututxline(&entry);
        libc::endutxent();
    }
}

/// Derive the 4-char ut_id from the terminal line name (e.g. "pts/0" → "/0  ").
fn id_from_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let start = bytes.len().saturating_sub(4);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

unsafe fn set_time(entry: &mut libc::utmpx) {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    entry.ut_tv = libc::__timeval {
        tv_sec: ts.tv_sec as i32,
        tv_usec: (ts.tv_nsec / 1000) as i32,
    };
}

fn copy_str<const N: usize>(dest: &mut [c_char; N], src: &str) {
    let bytes = src.as_bytes();
    let len = bytes.len().min(N - 1);
    for (i, &b) in bytes[..len].iter().enumerate() {
        dest[i] = b as c_char;
    }
}
