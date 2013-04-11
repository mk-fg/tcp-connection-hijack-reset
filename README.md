tcp-connection-hijack-reset
--------------------

Simple [scapy](http://www.secdev.org/projects/scapy/) + iptables/ipsets + nflog
tool to hijack and reset existing TCP connections (for both ends), established
from other pids.

Purpose is not some malicious DoS attacks but rather kicking hung state-machines
in otherwise nice software, while making the whole thing look like a random net
hiccup, which most apps are designed to handle.

If NFLOG is used (to get packets that should not pass netfilter, for instance),
requires [scapy-nflog-capture](https://github.com/mk-fg/scapy-nflog-capture).


Usage
--------------------

- "conn_cutter" ipset: `ipset create conn_cutter hash:ip,port`

- "OUTPUT" chain:

	```
	-A OUTPUT -j conn_cutter
	-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	...
	```

- "conn_cutter" chain (some lines wrapped):

	```
	-A conn_cutter ! -p tcp -j RETURN
	-A conn_cutter -m set ! --match-set conn_cutter src,src -j RETURN
	-A conn_cutter -p tcp -m recent --set --name conn_cutter --rsource
	-A conn_cutter -p tcp -m recent ! --rcheck --seconds 20\
		--hitcount 2 --name conn_cutter --rsource -j NFLOG
	-A conn_cutter -p tcp -m recent ! --rcheck --seconds 20\
		--hitcount 2 --name conn_cutter --rsource -j REJECT --reject-with tcp-reset
	```

- run: `tcp-connection-hijack-reset.py conn_cutter --pid 1234 --debug`

- result: both endpoints reliably get single RST packet and closed connection.


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
