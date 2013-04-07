tcp-connection-hijack-reset
--------------------

Simple [scapy](http://www.secdev.org/projects/scapy/)-based tool to hijack and
reset existing TCP connections, established from other pids.

Purpose is not some malicious DoS attacks but rather kicking hung state-machines
in otherwise nice software, while making the whole thing look like a random net
hiccup, which most apps are designed to handle.

Tool doesn't require any firewall configuration changes, but it flips network
interfaces into promiscuous mode for the time it runs.


Usage
--------------------

Imagine two hosts happily chatting over netcat:

	host1% ncat -v -l 0.0.0.0 1234
	Ncat: Listening on 0.0.0.0:1234.

	host2% ncat -v host1 1234
	Ncat: Connected to host1:1234.

Yet root on host2 doesn't want them to chat...

	host2# ./tcp-connection-hijack-reset.py --debug --remote-port 1234
	DEBUG:root:Waiting for noise on the session
	DEBUG:root:Session check, packet: <...>
	DEBUG:root:Found session (remote: host1)
	DEBUG:root:Collected: Ether / IP / TCP ...
	DEBUG:root:Captured seq, proceeding to termination
	DEBUG:root:Sending FIN: <...>

That should promptly terminate the connection.

Note that lacking implementation of some of the things described in an
"enhancements" section below, tool requires at least some traffic to pass on
connection, which is usually not the case with various hangs which need it the
most.

One simple soluton here is SO_KEEPALIVE socket flag, which can be enabled
system-wide even on linux with something like
[libkeepalive](http://libkeepalive.sourceforge.net/) in ld.so.preload and
further configured to send empty keepalive packets at shorter intervals than the
default 2h or so.

As any such packet has seq in it, and is enough for the thing to kill the
connection.


Possible enhancements
--------------------

- Will need to check if scapy supports capturing packets via
	[nflog](http://wiki.wireshark.org/CaptureSetup/NFLOG) - probably does already,
	or should be trivial to add, as underlying tcpdump definitely has support for
	it - and add an option for using it to acquire packets.

	Should give some performance boost and make the thing a bit more flexible at
	the expense of some required system configuration.

- Implement (or rather just copy from [cpiu](http://criu.org/),
	[ptrace-parasite](https://code.google.com/p/ptrace-parasite/) or similar
	project) a way to hijack pids and either do `getsockopt(sk, SOL_TCP,
	TCP_QUEUE_SEQ, ...)` in them or just close right there connections.

	At the moment, crtools still seem to require kernel patches and the voodoo
	approaches to shellcode generation and injection employed in these projects
	seem to need a bit of hacking to reuse - no nicely packaged lib available yet.

- Find some other (instant) way to spoof tcp seq numbers from kernel - ideally,
	some root-only /proc hook would just dump these - why the hell not?

	Wasn't able to find any, but didn't look hard enough to various netlink
	options available, so maybe there is a way already.


Similar tools
--------------------

- [dsniff](http://www.monkey.org/~dugsong/dsniff/) - has "tcpkill" binary that
	does very similar thing.

- [tcpkill](https://github.com/chartbeat/tcpkill) - standalone tcpkill tool from
	dsniff.

- [cutter](http://www.digitage.co.uk/digitage/software/cutter) - aims to solve
	similar problem, but on a router box (seem to work with conntrack tables
	only), and with some strange methods (generating noise on connection to get
	seq, which doesn't seem to work at all).
