# sshunt.py
SSH proxy with HASSH firewalling capabilities.


# Basic usage
- Edit allow/block lists below to your liking.

- Configure your sshd to listen on localhost only or a non-standard
  port by setting ListenAddress to 127.0.0.1 or Port to whatever you
  want.

    - If you opt to use a non-standard port, apply firewall rules
      accordingly.  This is an exercise left to the reader if you
      choose this method.

- Run this relay on port 22. Forward traffic to non-standard sshd port
  that was configured in the prior step.

- Incoming connections will be proxied through this. If it is a known
  bad tool, the connection will be dropped.

# Example

```# ./sshunt.py 192.168.59.131 22 127.0.0.1 22```