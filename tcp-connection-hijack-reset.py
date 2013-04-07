#!/usr/bin/env python
from __future__ import unicode_literals, print_function

from subprocess import Popen, PIPE, STDOUT
import itertools as it, operator as op, functools as ft
import os, sys

from scapy.all import *


class TCPBreaker(Automaton):

	ss_filter_port = ss_remote = None
	ss_intercept = list()

	def __init__(self, port, **atmt_kwz):
		self.ss_filter_port = port
		super(TCPBreaker, self).__init__(**atmt_kwz)


	def pkt_filter(self, pkt):
		if IP not in pkt or TCP not in pkt: raise KeyError
		elif pkt[TCP].dport == self.ss_filter_port: return pkt[IP].dst
		elif pkt[TCP].sport == self.ss_filter_port: return pkt[IP].src
		else: raise KeyError


	@ATMT.state(initial=1)
	def st_seek(self):
		log.debug('Waiting for noise on the session')
		pass

	@ATMT.receive_condition(st_seek)
	def check_packet(self, pkt):
		log.debug('Session check, packet: {}'.format(pkt.summary()))
		try: remote = self.pkt_filter(pkt)
		except KeyError: return
		raise self.st_collect(pkt).action_parameters(remote)
	@ATMT.action(check_packet)
	def break_link(self, remote):
		if not self.ss_remote:
			log.debug('Found session (remote: {})'.format(remote))
			self.ss_remote = remote

	@ATMT.timeout(st_seek, 3)
	def interception_done(self):
		if self.ss_remote and self.ss_intercept:
			log.debug('Session data collected, proceeding to termination')
			raise self.st_fin_send()
		log.debug('Waiting for session data')

	@ATMT.state()
	def st_collect(self, pkt):
		log.debug('Collected: {}'.format(pkt.summary()))
		self.ss_intercept.append(pkt)
		raise self.st_seek()

	@ATMT.state()
	def st_fin_send(self):
		log.debug('Sending FIN packet')
		pkt_eth, pkt_ip, pkt_tcp = op.itemgetter(Ether, IP, TCP)(self.ss_intercept[-1])
		ordered = lambda k1,v1,k2,v2,pkt_dir=(pkt_ip.dst != self.ss_remote):\
			dict(it.izip((k1,k2), (v1,v2) if pkt_dir else (v2,v1)))
		rst = Ether(**ordered('src', pkt_eth.dst, 'dst', pkt_eth.src))\
			/ IP(**ordered('src', pkt_ip.src, 'dst', pkt_ip.dst))\
			/ TCP(**dict(it.chain.from_iterable(p.viewitems() for p in (
				ordered('sport', pkt_tcp.sport, 'dport', pkt_tcp.dport),
				ordered('seq', pkt_tcp.seq, 'ack', pkt_tcp.ack),
				dict(flags=b'FA', window=pkt_tcp.window) ))))
		rst[TCP].ack += len(pkt_tcp.payload)
		log.debug('RST: {}'.format(rst.summary()))
		sendp(rst)
		self.stop()


def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='TCP connection breaking tool.'
			' Uses Linux tcp_diag interface or captured traffic to get connection sequence'
				' number and inject RST packet into it, killing it regardless of how active it is'
				' and without resorting to bruteforce-guessing of seq numbers.')
	parser.add_argument('port', type=int, help='TCP port of connection to close.')
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
	TCPBreaker(port=optz.port, store=False, filter='tcp and {}'.format(optz.bpf)).run()


if __name__ == '__main__': sys.exit(main())
