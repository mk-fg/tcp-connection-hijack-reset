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

- Create "conn_cutter" ipset: `ipset create conn_cutter hash:ip,port`

- Create "conn_cutter" chain (some lines wrapped):

	```
	-A conn_cutter ! -p tcp -j RETURN
	-A conn_cutter -m set ! --match-set conn_cutter src,src -j RETURN
	-A conn_cutter -p tcp -m recent --set --name conn_cutter --rsource
	-A conn_cutter -p tcp -m recent ! --rcheck --seconds 20\
		--hitcount 2 --name conn_cutter --rsource -j NFLOG
	-A conn_cutter -p tcp -m recent ! --rcheck --seconds 20\
		--hitcount 2 --name conn_cutter --rsource -j REJECT --reject-with tcp-reset
	```

	Note that due to one global "recent" netfilter tag used above, only one
	connection can be cut in 20 seconds (others will pass through this chain
	unharmed).

	This is done in case of rare pids which may bind() outgoing socket to a
	constant port, so that packets of the reconnection attempt from the same port
	won't get matched and pass.

- Update "OUTPUT" chain:

	```
	-I OUTPUT -j conn_cutter
	```

	That should be strictly *before* rules like `--state RELATED,ESTABLISHED -j
	ACCEPT`.

- Run: `tcp-connection-hijack-reset.py conn_cutter --pid 1234 --debug`

	Will pick single TCP connection of a specified pid (or raise error if there's
	more than one) and cut it, with a lots of noise about what it's doing (due to
	"--debug").

- Result: both endpoints should reliably get single RST packet and connection
	closed promptly.

See [this
post](http://blog.fraggod.net/2013/04/08/tcp-hijacking-for-the-greater-good.html)
on more details about what it all means and why it's there.


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
