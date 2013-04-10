tcp-connection-hijack-reset
--------------------

Simple [scapy](http://www.secdev.org/projects/scapy/) + iptables/ipsets + nflog
tool to hijack and reset existing TCP connections (for both ends), established
from other pids.

Purpose is not some malicious DoS attacks but rather kicking hung state-machines
in otherwise nice software, while making the whole thing look like a random net
hiccup, which most apps are designed to handle.


Usage
--------------------

To be updated.



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
