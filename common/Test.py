import ssh

ssh=ssh.ssh('10.10.88.192','Admin','admin')
ssh.connect()
log.warning(ssh.cmd('ls'))
