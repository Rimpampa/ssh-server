use anyhow::Context;
use uzers::os::unix::UserExt;

mod pam_appl;

fn main() -> anyhow::Result<()> {
    let username = std::env::args().nth(1).with_context(|| "[DEV] Missing usarname!")?;
    let password = rpassword::prompt_password(format!("{username}'s password: ")).with_context(|| "[DEV] During password prompt...")?;

    let user = uzers::get_user_by_name(&username).with_context(|| "[DEV] User does not exist!")?;

    let _session = pam_appl::Session::open(&username, &password)?;

    let (_pty, pts) = pty_process::blocking::open()?;

    pty_process::blocking::Command::new(user.shell())
        .arg("-i")
        .uid(user.uid())
        .gid(user.primary_group_id())
        .current_dir(user.home_dir())
        // .env("TERM", self.term.as_deref().unwrap_or("xterm-256color"))
        .env("HOME", user.home_dir())
        .env("USER", user.name())
        .env("LOGNAME", user.name())
        .env("SHELL", user.shell())
        .spawn(pts)?;

    Ok(())
}
