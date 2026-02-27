use nix::errno::Errno;
use nix::pty::{OpenptyResult, Winsize};
use nix::unistd::{ForkResult, dup2, fork, setsid};

use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};

#[derive(Clone, Default)]
pub struct Pty {
    // PTY negotiated size (cols, rows)
    size: Option<Winsize>,
    // terminal name (TERM)
    pub term: Option<String>,
    // raw master fd for ioctl window changes (use duplicated fd)
    master_fd: Option<i32>,
}

pub enum PtyFork {
    Child,
    Parent {
        fd: OwnedFd,
        child: nix::unistd::Pid,
    },
}

impl Pty {
    pub fn request(
        &mut self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        term: &str,
    ) {
        self.size = Some(Winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        });
        self.term = Some(term.to_string());
    }

    pub fn window_change(
        &mut self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), ()> {
        // attempt to resize PTY if we have a master fd
        let fd = self.master_fd.ok_or(())?;
        let ws = Winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        };
        // SAFETY: TODO
        unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
        self.size = Some(ws);
        Ok(())
    }

    /// Start a child process with a new PTY.
    ///
    /// # Safety
    ///
    /// Same safety requirements as [`fork()`].
    pub unsafe fn open(&mut self) -> Result<PtyFork, Errno> {
        let OpenptyResult { master, slave } = nix::pty::openpty(self.size.as_ref(), None)?;
        self.master_fd = Some(master.as_raw_fd());

        // SAFETY:
        // the safety requirements of fork are the same as the safety requirements of this function,
        // so the caller must ensure that those requirements are met before calling this function.
        match unsafe { fork()? } {
            ForkResult::Child => {
                let slave = slave.into_raw_fd();
                // Child: become session leader and set up slave PTY as controlling terminal
                let _ = setsid();

                // set controlling tty
                // SAFETY: TODO
                unsafe { libc::ioctl(slave, libc::TIOCSCTTY, 0) };

                // Redirect stdio to slave PTY
                let _ = dup2(slave, 0);
                let _ = dup2(slave, 1);
                let _ = dup2(slave, 2);

                Ok(PtyFork::Child)
            }
            ForkResult::Parent { child } => Ok(PtyFork::Parent { fd: master, child }),
        }
    }
}
