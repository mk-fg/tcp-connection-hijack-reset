#!/usr/bin/env python
from __future__ import print_function

from scapy.all import *

import itertools as it, operator as op, functools as ft
from subprocess import Popen, PIPE
from os.path import join
import os, sys, signal, re

from scapy_nflog import install_nflog_listener


class ConnMultipleMatches(Exception): pass
class ConnNotFound(Exception): pass


def get_endpoints(pid=None, port_local=None, port_remote=None):
	if pid: matches = list(get_endpoints_by_pid(pid))
	else:
		matches = list(get_endpoints_by_port(
			port_local=None, port_remote=None ))

	if not matches: raise ConnNotFound()
	if len(matches) > 1: raise ConnMultipleMatches(matches)

	local, remote = matches[0]
	return (inet_ntoa(struct.pack('<I', local[0] & 0xffffffff)), local[1]),\
		(inet_ntoa(struct.pack('<I', remote[0] & 0xffffffff)), remote[1])

def get_endpoints_by_port(port_local=None, port_remote=None):
	'Lookup connection for a specified port(s) in /proc/net/tcp table.'
	assert port_local or port_remote, (port_local, port_remote)
	with open('/proc/net/tcp') as src:
		src = iter(src)
		next(src) # skip header line
		for line in src:
			local, remote = (
				tuple(int(v, 16) for v in ep.split(':'))
				for ep in op.itemgetter(1, 2)(line.split()) )
			for ep, port in [(local, port_local), (remote, port_remote)]:
				if ep[1] == port: break
			else: continue
			yield local, remote

def get_endpoints_by_pid(pid):
	'Lookup connection(s) for a specified pid.'
	assert isinstance(pid, int), pid
	conns = dict()
	with open('/proc/net/tcp') as src:
		src = iter(src)
		next(src) # skip header line
		for line in src:
			line = line.split()
			conns[line[9]] = line[1], line[2]
	pid_fds = '/proc/{}/fd'.format(pid)
	for fd in os.listdir(pid_fds):
		match = re.search(r'^socket:\[(\d+)\]$', os.readlink(join(pid_fds, fd)))
		if not match: continue
		try: match = conns[match.group(1)]
		except KeyError: continue
		yield tuple(tuple(int(v, 16) for v in ep.split(':')) for ep in match)


def ipset_update(cmd, name, ip, port):
	if name is None: return
	assert cmd in ['add', 'del'], cmd
	log.debug('Updating ipset {!r} ({} {}:{})'.format(name, cmd, ip, port))
	if Popen(['ipset', '-!', cmd, name, '{},{}'.format(ip, port)]).wait():
		raise RuntimeError('Failed running ipset command, see error output above.')



class TCPBreaker(Automaton):

	ss_filter_port_local = ss_filter_port_remote = None
	ss_remote, ss_intercept = None, None

	def __init__(self, port_local, port_remote, **atmt_kwz):
		self.ss_filter_port_local, self.ss_filter_port_remote = port_local, port_remote
		atmt_kwz.setdefault('store', False)
		atmt_kwz.setdefault( 'filter',
			'tcp and src port {} and dst port {}'.format(port_local, port_remote) )
		super(TCPBreaker, self).__init__(**atmt_kwz)

	def pkt_filter(self, pkt):
		'Filter packets by ports in case of capture filter leaks or dissector bugs.'
		if {pkt[TCP].sport, pkt[TCP].dport} == {self.ss_filter_port_local, self.ss_filter_port_remote}:
			return pkt[IP].dst if pkt[TCP].sport == self.ss_filter_port_local else pkt[IP].src
		raise KeyError

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

	@ATMT.state()
	def st_collect(self, pkt):
		log.debug('Collected: {}'.format(pkt.summary()))
		self.ss_intercept = pkt
		raise self.st_rst_send()

	@ATMT.state()
	def st_rst_send(self):
		pkt_ip, pkt_tcp = op.itemgetter(IP, TCP)(self.ss_intercept)
		rst = IP(src=pkt_ip.src, dst=pkt_ip.dst)\
			/ TCP( flags='R', window=pkt_tcp.window,
				sport=pkt_tcp.sport, dport=pkt_tcp.dport,
				seq=pkt_tcp.seq, ack=pkt_tcp.ack )
		log.debug('Sending RST: {!r}'.format(rst))
		send(rst)

		# Finish
		os.kill(os.getpid(), signal.SIGINT)
		self.stop()



def main(argv=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='TCP connection breaking tool.'
			' Finds connection with a specified parameters and adds local'
				' ip:port to the specified ipset, so firewall can cut it on first activity'
				' (with something like "-j REJECT --reject-with tcp-reset").'
			' Also uses captured traffic to get connection sequence number and send'
				' RST packet to remote endpoint, removing ip:port from ipset upon success.')

	parser.add_argument('ipset_name',
		help='Name of the ipset to temporarily insert local ip:port to.'
			' Should be used in some iptables filter rule,'
				' rejecting outgoing packets from it with tcp-reset packet.'
			' If not specified, no ipset updates will be performed.')

	parser.add_argument('--pid', type=int,
		help='Process ID to terminate connection of.')
	# parser.add_argument('-i', '--interactive', action='store_true',
	# 	help='With --pid option, allow to pick connection in CLI, if there is more then one.')

	parser.add_argument('--port', type=int,
		help='TCP port of local (unless --remote-port is specified) connection to close.')
	parser.add_argument('-d', '--remote-port', action='store_true',
		help='Treat port argument as remote, not local one.')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args(sys.argv[1:] if argv is None else argv)

	import logging
	logging.basicConfig(level=logging.DEBUG if optz.debug else logging.INFO)
	global log
	log = logging.getLogger()

	## Configure scapy
	# It should be traffic to/from same machine - no promisc-mode necessary
	conf.promisc = conf.sniff_promisc = False
	# Disables "Sent 1 packets." line
	conf.verb = False
	# Install NFLOG listener
	install_nflog_listener()

	if optz.port:
		local, remote = get_endpoints(
			**{'port_local' if not optz.remote_port else 'port_remote': optz.port} )
	elif optz.pid: local, remote = get_endpoints(pid=optz.pid)
	else: parser.error('No connection-picking criterias specified.')

	log.debug('Found connection: {0[0]}:{0[1]} -> {1[0]}:{1[1]}'.format(local, remote))

	ipset_update('add', optz.ipset_name, *local)
	try: TCPBreaker(port_local=local[1], port_remote=remote[1]).run()
	finally: ipset_update('del', optz.ipset_name, *local)


if __name__ == '__main__': sys.exit(main())
