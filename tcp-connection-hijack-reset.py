#!/usr/bin/env python
from __future__ import unicode_literals, print_function

from subprocess import Popen, PIPE, STDOUT
import itertools as it, operator as op, functools as ft
import os, sys

from scapy.all import *


class TCPBreaker(Automaton):

	ss_filter_port_local = ss_filter_port_remote = None
	ss_remote, ss_intercept = None, list()

	def __init__(self, port_local=None, port_remote=None, **atmt_kwz):
		self.ss_filter_port_local, self.ss_filter_port_remote = port_local, port_remote
		super(TCPBreaker, self).__init__(**atmt_kwz)


	def pkt_filter(self, pkt):
		'Filter packets by additional (to bpf) criterias, passed on init.'
		if IP not in pkt or TCP not in pkt: raise KeyError
		if pkt.seq == 0: raise KeyError # ack-bait packet
		for port, res_dport, res_sport in [
				(self.ss_filter_port_local, 'src', 'dst'),
				(self.ss_filter_port_remote, 'dst', 'src') ]:
			if port is None: continue
			for chk, res in it.izip(['dport', 'sport'], [res_dport, res_sport]):
				if getattr(pkt[TCP], chk) == port: return getattr(pkt[IP], res)
		raise KeyError

	def get_remote_by_port(self):
		'Lookup remote host for a specified port(s) in tcp connection table.'
		with open('/proc/net/tcp') as src:
			src = iter(src)
			next(src) # skip header line
			for line in src:
				local, remote = (
					tuple(int(v, 16) for v in ep.split(':'))
					for ep in op.itemgetter(1, 2)(line.split()) )
				for (ep, port) in [
						(local, self.ss_filter_port_local),
						(remote, self.ss_filter_port_remote) ]:
					if ep[1] == port: break
				else: continue
				return inet_ntoa(struct.pack(b'<I', remote[0] & 0xffffffff)), local[1], remote[1]
			else: raise KeyError


	@ATMT.state(initial=1)
	def st_seek(self):
		log.debug('Waiting for noise on the session')

	@ATMT.receive_condition(st_seek)
	def check_packet(self, pkt):
		log.debug('Session check, packet: {!r}'.format(pkt))
		try: remote = self.pkt_filter(pkt)
		except KeyError: return
		raise self.st_collect(pkt).action_parameters(remote)
	@ATMT.action(check_packet)
	def break_link(self, remote):
		if not self.ss_remote:
			log.debug('Found session (remote: {})'.format(remote))
			self.ss_remote = remote

	@ATMT.timeout(st_seek, 1)
	def interception_done(self):
		if self.ss_remote and self.ss_intercept:
			log.debug('Captured seq, proceeding to termination')
			raise self.st_rst_send()
		else:
			remote, sport, dport = self.get_remote_by_port()
			log.debug('Provoking remote ({}) to send correcting ACK'.format(remote))
			# Contrary to what digitage.co.uk/digitage/software/cutter says, it doesn't work ;(
			pkt = IP(dst=remote)/TCP(sport=sport, dport=dport, seq=0, flags=b'PA')#/b'XXX'
			send(pkt)

	@ATMT.state()
	def st_collect(self, pkt):
		log.debug('Collected: {}'.format(pkt.summary()))
		self.ss_intercept.append(pkt)
		raise self.st_seek()

	@ATMT.state()
	def st_rst_send(self):
		pkt_eth, pkt_ip, pkt_tcp = op.itemgetter(Ether, IP, TCP)(self.ss_intercept[-1])
		ordered = lambda k1,v1,k2,v2,pkt_dir=(pkt_ip.dst == self.ss_remote):\
			dict(it.izip((k1,k2), (v1,v2) if pkt_dir else (v2,v1)))
		rst = Ether(**ordered('dst', pkt_eth.dst, 'src', pkt_eth.src))\
			/ IP(**ordered('src', pkt_ip.src, 'dst', pkt_ip.dst))\
			/ TCP(**dict(it.chain.from_iterable(p.viewitems() for p in (
				ordered('sport', pkt_tcp.sport, 'dport', pkt_tcp.dport),
				ordered('seq', pkt_tcp.seq, 'ack', pkt_tcp.ack),
				dict(flags=b'FA', window=pkt_tcp.window) ))))
		rst[TCP].ack += len(pkt_tcp.payload)
		log.debug('Sending RST: {!r}'.format(rst))
		sendp(rst)
		self.stop()


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='TCP connection breaking tool.'
			' Uses Linux tcp_diag interface or captured traffic to get connection sequence'
				' number and inject RST packet into it, killing it regardless of how active it is'
				' and without resorting to bruteforce-guessing of seq numbers.')
	parser.add_argument('port', type=int,
		help='TCP port of local (unless --remote-port is specified) connection to close.')
	parser.add_argument('-d', '--remote-port', action='store_true',
		help='Treat port argument as remote, not local one.')
	parser.add_argument('-f', '--bpf', metavar='bpf_filter_string',
		help='BPF (Berkley Packet Filter) format string to'
				' passively snatch packets on relevant connection with.'
			' Prepended with "tcp and" for convenience,'
				' so that "port 5190" argument will result in "tcp and port 5190" filter.'
			' If not specified, auto-generated from provided IPs'
				' and/or port numbers (e.g. "port 5190" from "5190" as port argument).')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args(sys.argv[1:] if argv is None else argv)

	import logging
	logging.basicConfig(level=logging.DEBUG if optz.debug else logging.INFO)
	global log
	log = logging.getLogger()

	if not optz.bpf: optz.bpf = 'port {}'.format(optz.port)
	TCPBreaker(
		store=False, filter='tcp and {}'.format(optz.bpf),
		**{('port_local' if not optz.remote_port else 'port_remote'): optz.port} ).run()


if __name__ == '__main__': sys.exit(main())
