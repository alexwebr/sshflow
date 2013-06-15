sshflow
=======

This tool is a proof-of-concept to analyze packet capture files
by looking for SSH handshakes and then profiling those sessions
to guess what (if anything) is being tunneled.

Plugins
-------

Presently, the tool detects interactive sessions, nested tunnels,
X11 forwarding, and server-to-client/client-to-server file copies.

Usage
-----

You need Python 2.7 and the dpkt library.

`$ ./sshflow packetcapture.pcap`

Assumptions
-----------

It makes a number of assumptions:
- aes-ctr with hmac-md5 is used as a cipher suite. This is out
  of sheer laziness.

- Only a single channel (http://www.ietf.org/rfc/rfc4254.txt) is
  in active use per SSH connection.

- That all the SSH connections in a .pcap will always have a unique
  (client ip, client ephemeral port, server ip, server port)

