Intermidiate process between the SSH server and the user process
which handles PAM authentication.

Usage:
```sh
ssh-user username peer_ip:peer_port
```
where
- `username` is the username that will become the owener of the child process
- `peer_ip:peer_port` is the socket from which the remote user is communicating

e.g. For the user foo with IP 192.168.0.1 and port 48392 you would call:
```sh
ssh-user foo 192.168.0.1:48392
```
