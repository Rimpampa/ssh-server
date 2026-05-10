use std::io::{Write, pipe};
use std::{os::unix::process::CommandExt, process::Command};

use uzers::os::unix::UserExt;

mod pam;

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
    let repeat = rpassword::prompt_password("Repeat password: ").unwrap();
    assert!(password == repeat);

    let status = Command::new("useradd")
        .args(["-m", username])
        .status()
        .unwrap();
    assert!(status.success(), "useradd failed!");

    let (output, mut input) = pipe().unwrap();
    let mut child = Command::new("chpasswd").stdin(output).spawn().unwrap();

    let data = format!("{username}:{password}");
    input.write_all(data.as_bytes()).unwrap();

    drop(input);

    let status = child.wait().unwrap();
    assert!(status.success(), "chpasswd failed!");

    (uzers::get_user_by_name(username).unwrap(), password)
}
