use std::{os::unix::process::CommandExt, process::Command};

use uzers::os::unix::UserExt;

mod pam;
mod crypt;

fn main() {
    let mut args = std::env::args().skip(1);
    let username = args.next().unwrap();
    let host = args.next().unwrap();

    let (user, password) = match uzers::get_user_by_name(&username) {
        Some(user) => (
            user,
            rpassword::prompt_password(format!("{username}'s password: ")).unwrap(),
        ),
        None => new_user(&username),
    };

    let _session = pam::Session::open(&username, &password, &host).unwrap();

    Command::new(user.shell())
        .arg("-i")
        .gid(user.primary_group_id())
        .uid(user.uid())
        .current_dir(user.home_dir())
        .env("TERM", "xterm-256color")
        .env("HOME", user.home_dir())
        .env("USER", user.name())
        .env("LOGNAME", user.name())
        .env("SHELL", user.shell())
        .status()
        .unwrap();
}

fn new_user(username: &str) -> (uzers::User, String) {
    let password = rpassword::prompt_password(format!("New {username}'s password: ")).unwrap();
    let repeat = rpassword::prompt_password(format!("Repeat password: ")).unwrap();
    assert!(password == repeat);

    let salt = crypt::gensalt(None, 0, None).unwrap();
    let password = std::ffi::CString::new(password).unwrap();
    let password = crypt::crypt(&password, &salt).unwrap();
    let password = password.into_string().unwrap();

    // TODO: from useradd(8)
    // Note: This option is not recommended because the password (or encrypted password)
    //       will be visible by users listing the processes.
    Command::new("useradd")
        .args(["-m", username, "-p", &password])
        .status()
        .unwrap();

    (uzers::get_user_by_name(username).unwrap(), password)
}
