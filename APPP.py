#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# APPP (PYTHON IMPLEMENTATION OF APJP http://code.google.com/p/apjp/)
#
# Copyright (C) 2012 Fartersoft
#
# This program contains code copied from, modified from, or inspired by multiple open source programs as documented in comments.
#
# This program is released under the terms of the GNU General Public License (GPL) version 2 or later.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import errno
import getopt
from hashlib import sha256
import logging
import os
from re import match,sub
import socket
import select
import ssl
import sys
from threading import activeCount, current_thread, Thread
from time import time, sleep
import base64

try:
	from OpenSSL import crypto
except ImportError:
	print('Please install pyOpenSSL (https://launchpad.net/pyopenssl) first!')
	sys.exit(1)

__APP__ = 'APPP'
__VERSION__ = '0.2.0'

BUFFER_LENGTH = 4096
TIMEOUT = 6

flag_exit = False
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s APPP[%(threadName)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
ch.setFormatter(formatter)
logger.addHandler(ch)
dns = {}

def safebytes2(s):
	b = bytearray(len(s))
	for i in xrange(len(s)):
		b[i] = ord(s[i])
	return b

def safebytes3(s):
	return s

if sys.version < '3':
	from ConfigParser import SafeConfigParser
	safebytes = safebytes2
else:
	from configparser import SafeConfigParser
	safebytes = safebytes3

# Modified from https://bitbucket.org/timv/python-extras/src/faee53d0e469/pdfminer/arcfour.py
class Arcfour(object):

	def __init__(self, s):
		self.s, self.i, self.j = (s[:], 0, 0)
		return

	def process(self, data):
		pre = safebytes(data)
		post = bytearray(len(data))
		(i, j) = (self.i, self.j)
		s = self.s
		p = 0
		for c in pre:
			i = (i+1) % 256
			j = (j+s[i]) % 256
			(s[i], s[j]) = (s[j], s[i])
			k = s[(s[i]+s[j]) % 256]
			post[p] = c ^ k
			p += 1
		(self.i, self.j) = (i, j)
		return post

# Slightly modified from http://mitmproxy.org
def create_ca():
	key = crypto.PKey()
	key.generate_key(crypto.TYPE_RSA, 1024)
	ca = crypto.X509()
	ca.set_serial_number(int(time()*10000))
	ca.set_version(2)
	ca.get_subject().CN = "APPP"
	ca.get_subject().O = "APPP"
	ca.gmtime_adj_notBefore(0)
	ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
	ca.set_issuer(ca.get_subject())
	ca.set_pubkey(key)
	ca.add_extensions([
	  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
	  crypto.X509Extension(b"nsCertType", True, b"sslCA"),
	  crypto.X509Extension(b"extendedKeyUsage", True,
		b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"),
	  crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
	  crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca),
	  ])
	ca.sign(key, "sha1")
	return key, ca

def dump_ca():
	try:
		if os.path.getsize('APPP.pks') > 0 and os.path.getsize('APPP.pem') > 0:
			logger.debug('APPP.pks and APPP.pem already exist. Skipping...')
			return True
	except os.error:
		pass
	logger.info('Creating new APPP certificates')
	try:
		key, ca = create_ca()
		# Dump the CA plus private key
		f = open("APPP.pks", "w+b")
		f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
		f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
		f.close()
		# Dump the certificate in PEM format
		f = open("APPP.pem", "w+b")
		f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
		f.close()
	except Exception as e:
		logger.critical("Exception encountered while creating CA certificate: %s" % str(e))
		return False
	else:
		return True

def dummy_cert(commonname, certdir = 'crt', ca = 'APPP.pks', sans = ''):
	if not os.path.exists(certdir):
		os.makedirs(certdir)
	namehash = sha256(commonname.encode()).hexdigest()
	certpath = os.path.join(certdir, namehash + ".pem")
	if os.path.exists(certpath) and os.path.getsize(certpath) > 0:
		logger.debug('Certificate for %s already exists.', commonname)
		return certpath
	logger.debug('Creating certificate for %s.', commonname)
	ss = []
	for i in sans:
		ss.append("DNS: %s"%i)
	ss = ", ".join(ss).encode()

	if ca:
		f = open(ca, "r")
		raw = f.read()
		ca = crypto.load_certificate(crypto.FILETYPE_PEM, raw)
		key = crypto.load_privatekey(crypto.FILETYPE_PEM, raw)
		f.close()
	else:
		return None

	req = crypto.X509Req()
	subj = req.get_subject()
	subj.CN = commonname
	req.set_pubkey(ca.get_pubkey())
	req.sign(key, "sha1")
	if ss:
		req.add_extensions([crypto.X509Extension(b"subjectAltName", True, ss)])

	cert = crypto.X509()
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
	cert.set_issuer(ca.get_subject())
	cert.set_subject(req.get_subject())
	cert.set_serial_number(int(time()*10000))
	if ss:
		cert.add_extensions([crypto.X509Extension(b"subjectAltName", True, ss)])
	cert.set_pubkey(req.get_pubkey())
	cert.sign(key, "sha1")

	f = open(certpath, "w+b")
	f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	f.close()

	return certpath

def create_connection(address, socket_create_connection):
	address1 = address[0].split('.')
	i = 0
	while i < len(address1):
		address2 = '.'.join(address1[i::])
		for key in dns.keys():
			if address2 == key:
				values = dns.get(key)
				j = 0
				while j < len(values):
					if values[j][1] > 0:
						address3 = (values[j][0], address[1])
						try:
							logger.info('Create connection to %s:%d' % address3)
							
							connection = socket_create_connection(address3)
							if values[j][1] < 5:
								values[j] = (values[j][0], values[j][1] + 1)
							return connection
						except Exception as e:
							logger.info('Can not create connection to %s:%d' % address3)
							
							values[j] = (values[j][0], values[j][1] - 1)
					j = j + 1
		i = i + 1
	connection = socket_create_connection(address)
	return connection

# Code framework modified from http://code.google.com/p/python-proxy/
class ConnectionHandler:
	def __init__(self, server, conn):
		current_thread().name = current_thread().name + '-' +  str(abs(current_thread().ident))
		self.server = server
		self.client, self.peer = conn
		logger.info('Received connection from %s:%d' % (self.peer[0], self.peer[1]))
		self.ssl_mode = False
		self.client_hdrs = ''
		self.data_size = 0
		self.client_buffer = b''
		self.req_read = False
		self.resp_read = False

		try:
			if self.process():
				logger.info('Request from %s:%d successfully processed' % (self.peer[0], self.peer[1]))
			else:
				logger.warning('Failed to process request from %s:%d' % (self.peer[0], self.peer[1]))
		except (KeyboardInterrupt, SystemExit):
			global flag_exit
			flag_exit = True
			raise
		except Exception as e:
			logger.error('Exception encountered processing request from %s:%d: %s' % (self.peer[0], self.peer[1], str(e)))
		try:
			self.client.close()
			self.target.close()
		except:
			pass
		return

	def process(self):
		while True:
			s = self.client.recv(BUFFER_LENGTH)
			self.client_buffer += s
			end = self.client_buffer.find(b'\r\n\r\n')
			if len(s) == 0:
				self.req_read = True
				break
			if end != -1:
				break
		if end == -1:
			logger.error('No correctly formatted request header received.')
			return False
		self.client_hdrs = self.client_buffer[:end+4].decode()
		logger.debug('Request headers:\r\n' + self.client_hdrs)

		self.method, self.url, self.version = list(self.client_hdrs.split('\r\n')[0].split())

		# APJP_REMOTE < 0.8.4 remove headers remotely.
		# These need to be removed locally for APJP_REMOTE >= 0.8.4.
		# Fix by APJP author Jeroen Van Steirteghem
		self.client_hdrs = sub(r'(?i)^([A-Z]+) https?:\/\/[^\/]+\/', r'\1' + ' /', self.client_hdrs)
		self.client_hdrs = sub(r'(?i)HTTP\/1\.1\r\n', 'HTTP/1.0\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nConnection: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nProxy-Connection: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nProxy-Authorization: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nTE: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nKeep-Alive: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nTrailer: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\nTransfer-Encoding: [^\r\n]+\r\n', '\r\n', self.client_hdrs);
		self.client_hdrs = sub(r'(?i)\r\n\r\n', '\r\nConnection: close\r\n\r\n', self.client_hdrs);
		self.client_buffer = self.client_hdrs.encode() + self.client_buffer[end+4:]

		if self.method == 'CONNECT':
			logger.debug('Initiating encryption...')
			try:
				# Safe to assume there is only header?
				self.client.sendall(b'HTTP/1.0 200 OK\r\nPROXY-AGENT: Python\r\nCONNECTION: Keep-Alive\r\n\r\n')
				self.client_buffer = b''
				cert = dummy_cert(self.url.split(':')[0])
				self.client = ssl.wrap_socket(self.client, server_side=True,
					certfile=cert, keyfile="APPP.pks", cert_reqs=ssl.CERT_NONE,
					ssl_version=ssl.PROTOCOL_SSLv23)
			except Exception as e:
				logger.error("Exception encountered encrypting socket connection: %s" % str(e))
				return False
			self.ssl_mode = True
			return self.process()

		self.scheme = 'HTTPS' if self.ssl_mode else self.url.split(':')[0].upper()

		# We need the Content-Length header to calculate POST data size
		end = self.client_hdrs.find('Content-Length:')
		if end != -1:
			self.data_size = int(self.client_hdrs[end + 16:].split()[0])
		logger.debug('Request data size: %d' % self.data_size)
		if self.data_size + len(self.client_hdrs) == len(self.client_buffer):
			self.req_read = True
		
		try:
			s = 'POST %s HTTP/1.0\r\n' % self.server[self.scheme + '_URL_RESOURCE']
			s = s + 'Accept-Encoding: identity\r\n'
			s = s + 'Connection: close\r\n'
			s = s + 'Content-Length: %s\r\n' % str(len(self.client_hdrs) + self.data_size)
			s = s + 'Content-Type: application/x-www-form-urlencoded\r\n'
			
			if self.server[self.scheme + '_URL_SCHEME'] == 'HTTP':
				if self.server[self.scheme + '_URL_PORT'] == 80:
					s = s + 'Host: %s\r\n' % self.server[self.scheme + '_URL_ADDR']
				else:
					s = s + 'Host: %s:%d\r\n' % (self.server[self.scheme + '_URL_ADDR'], self.server[self.scheme + '_URL_PORT'])
			else:
				if self.server[self.scheme + '_URL_SCHEME'] == 'HTTPS':
					if self.server[self.scheme + '_URL_PORT'] == 443:
						s = s + 'Host: %s\r\n' % self.server[self.scheme + '_URL_ADDR']
					else:
						s = s + 'Host: %s:%d\r\n' % (self.server[self.scheme + '_URL_ADDR'], self.server[self.scheme + '_URL_PORT'])
			
			s = s + 'User-Agent: %s\r\n' % self.server['APPP_UA']
			
			i = 1
			while i <= 5:
				if self.server['CUSTOM_HEADER' + str(i)] != '':
					s = s + self.server['CUSTOM_HEADER' + str(i)] + '\r\n'
				i = i + 1
			
			if self.server['HTTP_PROXY_ADDR'] and self.server[self.scheme + '_URL_SCHEME'] == 'HTTP':
				if self.server['HTTP_PROXY_USER']:
					authorization = base64.standard_b64encode((self.server['HTTP_PROXY_USER'] + ':' + self.server['HTTP_PROXY_PASS']).encode()).decode()
					s = s + 'Proxy-Authorization: Basic %s\r\n' % authorization
				s = s + '\r\n'
				
				self.target = socket.create_connection((self.server['HTTP_PROXY_ADDR'], self.server['HTTP_PROXY_PORT']))
			else:
				if self.server['HTTPS_PROXY_ADDR'] and self.server[self.scheme + '_URL_SCHEME'] == 'HTTPS':
					s = s + '\r\n'
					
					def socket_create_connection(address):
						connection = socket.create_connection((self.server['HTTPS_PROXY_ADDR'], self.server['HTTPS_PROXY_PORT']))
						
						s2 = 'CONNECT %s:%d HTTP/1.0\r\n' % address
						if self.server['HTTP_PROXY_USER']:
							authorization = base64.standard_b64encode((self.server['HTTPS_PROXY_USER'] + ':' + self.server['HTTPS_PROXY_PASS']).encode()).decode()
							s2 = s2 + 'Proxy-Authorization: Basic %s\r\n' % authorization
						s2 = s2 + '\r\n'
						
						connection.send(s2.encode())
						
						s3 = ''
						while True:
							s2 = connection.recv(BUFFER_LENGTH)
							s3 = s3 + s2
							end = s3.find(b'\r\n\r\n')
							if len(s2) == 0:
								break
							if end != -1:
								break
						
						s2 = s3.split(b'\r\n')[0]
						if s2.split()[1] != b'200':
							connection.close()
							
							raise Exception('Can not create connection to %s:%d' % address)
						
						return connection
					
					self.target = create_connection((self.server[self.scheme + '_URL_ADDR'], self.server[self.scheme + '_URL_PORT']), socket_create_connection)
					self.target = ssl.wrap_socket(self.target, ssl_version = ssl.PROTOCOL_SSLv23)
					self.target.do_handshake()
				else:
					s = s + '\r\n'
					
					def socket_create_connection(address):
						return socket.create_connection(address)
					
					self.target = create_connection((self.server[self.scheme + '_URL_ADDR'], self.server[self.scheme + '_URL_PORT']), socket_create_connection)
					if self.server[self.scheme + '_URL_SCHEME'] == "HTTPS":
						self.target = ssl.wrap_socket(self.target, ssl_version = ssl.PROTOCOL_SSLv23)
						self.target.do_handshake()
			
			logger.debug('Forwarding request to %s:%d\r\n' % (self.server[self.scheme + '_URL_ADDR'], self.server[self.scheme + '_URL_PORT']) + s)
			
			self.target.send(s.encode())
			self._read_write(self.client_buffer, self.req_read, self.client, self.target)
			self.client_buffer = b''
		except Exception as e:
			logger.error("Exception encountered forwarding request: %s" % str(e))
			return False

		while True:
			s = self.target.recv(BUFFER_LENGTH)
			self.client_buffer += s
			end = self.client_buffer.find(b'\r\n\r\n')
			if len(s) == 0:
				self.resp_read = True
				break
			if end != -1:
				break
		if end == -1:
			logger.error('No correctly formatted response header received.')
			logger.debug(self.client_buffer.decode())
			return False

		s = self.client_buffer[:end+4].decode()
		if s.split('\r\n')[0].split()[1] in ('200'):
			logger.info('Received response: ' + s.split('\r\n')[0])
		else:
			logger.warning('Received response: ' + s)
			return False
		self.client_buffer = self.client_buffer[end+4:]
		self._read_write(self.client_buffer, self.resp_read, self.target, self.client)
		self.client_buffer = b''
		return True

	def _read_write(self, initial_cont, initial_only, in_sock, out_sock):
		rc4 = Arcfour(self.server['APPP_RC4'])
		if initial_cont: out_sock.send(bytes(rc4.process(initial_cont)))
		if initial_only: return
		time_out_max = self.server['TIMEOUT']
		count = 0
		while 1:
			count += 1
			(recv, _, error) = select.select([in_sock], [], [in_sock, out_sock], 0.5)
			if error:
				break
			if recv:
				data = in_sock.recv(BUFFER_LENGTH)
				if data:
					try:
						out_sock.send(bytes(rc4.process(data)))
					except IOError as e:
						if e.errno == errno.EPIPE:
							break
					else:
						count = 0
			if count == time_out_max:
				break
		return

def spawn(tgt=None, args=(), name=None, daemon=True):
	t = Thread(name=name, target=tgt, args=args)
	t.setDaemon(daemon)
	t.start()
	return t

def start_server(server, handler = ConnectionHandler):
	try:
		try:
			soc = socket.socket(socket.AF_INET6)
			soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			try:
				soc.bind((server['APPP_ADDR'], server['APPP_PORT'], 0, 0))
			except socket.error:
				try:
					sockaddr = socket.getaddrinfo(server['APPP_ADDR'], server['APPP_PORT'])
					if len(sockaddr) <= 0 or len(sockaddr[0][4]) < 4: raise socket.error
					sockaddr = sockaddr[0][4]
					soc.bind((server['APPP_ADDR'], server['APPP_PORT'], sockaddr[2], sockaddr[3]))
				except socket.error as e:
					if server['APPP_ADDR'].find(':') != -1:
						logger.error('Binding to %s:%d failed: %s' % (server['APPP_ADDR'], server['APPP_PORT'], str(e)))
						return
					else:
						raise
				except Exception:
					raise
			except Exception:
				raise
		except socket.error: # IPv6 not usable
			try:
				soc = socket.socket(socket.AF_INET)
				soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				soc.bind((server['APPP_ADDR'], server['APPP_PORT']))
			except socket.error as e:
				logger.error('Binding to %s:%d failed: %s' % (server['APPP_ADDR'], server['APPP_PORT'], str(e)))
				return
			except Exception:
				raise
		except Exception:
			raise
		sockaddr = soc.getsockname()
		logger.info('Listening on %s:%s.' % (sockaddr[0], sockaddr[1]))
		soc.listen(100)
		if server['HTTP_TEST_SITE']: spawn(test, (server,'http'), name=current_thread().name)
		if server['HTTPS_TEST_SITE']: spawn(test, (server,'https', ), name=current_thread().name)
		while True:
			spawn(tgt=handler, args=(server, soc.accept()), name=current_thread().name)
	except (KeyboardInterrupt, SystemExit):
		logger.debug('Received termination request.')
		global flag_exit
		flag_exit  = True
		raise
	except Exception as e:
		logger.error('Unexpected exception encountered: %s' % str(e))

def test(server, scheme):
	current_thread().name = current_thread().name + '-TEST'
	h = scheme.upper()
	try:
		# APPP could be listening on all interfaces
		# create_connection can't handle '::' on WinXP
		addr = server['APPP_ADDR'] if (server['APPP_ADDR'] and server['APPP_ADDR'] != '::' and server['APPP_ADDR'] != '0.0.0.0') else socket.gethostbyname(socket.gethostname())
		try:
			s = socket.create_connection((addr, server['APPP_PORT']))
		except socket.error:
			try:
				sockaddr = socket.getaddrinfo(addr, server['APPP_PORT'])[0][4]
				s = socket.create_connection((sockaddr[0], sockaddr[1]))
			except socket.error as e:
				logger.error('APPP connectivity test to ' + scheme + '://' + server[h + '_TEST_SITE'] + ' failed: ' + str(e))
				return
			except Exception:
				raise
		except Exception:
			raise
		s.send(('HEAD ' + scheme + '://' + server[h + '_TEST_SITE'] + '/ HTTP/1.0\r\nHost: ' + server[h + '_TEST_SITE'] + '\r\n\r\n').encode())
		logger.info('Testing APPP connectivity to ' + scheme + '://' + server[h + '_TEST_SITE'])
		count = 0
		r = b''
		while 1:
			count += 1
			(recv, _, error) = select.select([s], [], [], 3)
			if error:
				break
			if recv:
				data = s.recv(BUFFER_LENGTH)
				if data:
					r += data
					if r.find(b'\r\n') != -1:
						break
					count = 0
			if count == TIMEOUT/3:
				break
		if r.find(b'\r\n') == -1:
			logger.error('APPP connectivity test to ' + scheme + '://' + server[h + '_TEST_SITE'] + ' failed: no correctly formatted response header received.')
		else:
			r = r.split(b'\r\n')[0]
			if r.split()[1] in (b'200', b'301', b'302'):
				logger.info('APPP connectivity test to ' + scheme + '://' + server[h + '_TEST_SITE'] + ' successful!')
			else:
				logger.error('APPP connectivity test to ' + scheme + '://' + server[h + '_TEST_SITE'] + ' failed: ' + r.decode())
		s.close()
	except (KeyboardInterrupt, SystemExit):
		logger.debug('Received termination request.')
		global flag_exit
		flag_exit  = True
		raise
	except Exception as e:
		logger.error('APPP connectivity test to ' + scheme + '://' + server[h + '_TEST_SITE'] + ' failed: ' + str(e))

def config(cfg, srv):
	try:
		logger.info('Processing [' + srv + '] configurations')
		
		server = dict(cfg.items(srv))
		
		server['APPP_UA'] = server['APPP_UA'] if server['APPP_UA'] else 'Python/' + sys.version.split()[0]
		server['APPP_PORT'] = cfg.getint(srv, 'APPP_PORT')
		server['TIMEOUT'] = cfg.getint(srv, 'TIMEOUT')
		
		if server['APPP_ADDR']:
			try:
				addr = socket.getaddrinfo(server['APPP_ADDR'], server['APPP_PORT'])
			except socket.gaierror as e:
				logger.critical('Failed to process APPP_ADDR:APPP_PORT settings (%s:%s): %s', server['APPP_ADDR'], server['APPP_PORT'], str(e))
				return None
			except Exception:
				raise
		
		for i in ('HTTP', 'HTTPS'):
			if server[i + '_PROXY_ADDR']:
				server[i + '_PROXY_PORT'] = int(server[i + '_PROXY_PORT'])
			
			server[i + '_URL_SCHEME'], server[i + '_URL_ADDR'], server[i + '_URL_PORT'], server[i + '_URL_RESOURCE'] = match(r"(http[s]?)://([0-9a-z\.\-]+)(:[0-9]+)?(/.*)", server[i + '_URL']).groups()
			
			server[i + '_URL_SCHEME'] = server[i + '_URL_SCHEME'].upper()
			
			if server[i + '_URL_PORT'] is None:
				if server[i + '_URL_SCHEME'] == 'HTTP':
					server[i + '_URL_PORT'] = 80
				elif server[i + '_URL_SCHEME'] == 'HTTPS':
					server[i + '_URL_PORT'] = 443
				else:
					logger.critical('Incorrect format: %s: %s', i + '_URL', server[i + '_URL'])
					return None
			else:
				server[i + '_URL_PORT'] = int(server[i + '_URL_PORT'][1:])
			
			if server[i + '_PROXY_ADDR']:
				try:
					addr = socket.getaddrinfo(server[i + '_PROXY_ADDR'], server[i + '_PROXY_PORT'])
				except socket.gaierror as e:
					logger.critical('Failed to process %s_PROXY settings (%s:%s): %s', i, proxy[0], proxy[1], str(e))
					return None
				except Exception:
					raise

		# Calculate ARCFOUR vector only once
		s = list(range(256))
		j = 0
		key = server['APPP_KEY']
		if not key:
			logger.critical('No APPP_KEY defined.')
			return None
		klen = len(key)
		for i in range(256):
			j = (j + s[i] + ord(key[i % klen])) % 256
			(s[i], s[j]) = (s[j], s[i])
		server['APPP_RC4'] = s
		if logger.isEnabledFor(logging.DEBUG):
			logger.debug('Using [' + srv + '] configurations:')
			for i in server:
				logger.debug(i + ': ' + str(server[i]))
		return server

	except Exception as e:
		logger.critical('Failed to process [' + srv + '] configuration: ' + str(e))
		return None

def usage():
	print('''
APPP %s (PYTHON IMPLEMENTATION OF APJP, A PHP/JAVA PROXY http://code.google.com/p/apjp/)

commandline options:

-a,--all	start all servers defined in APPP.ini
-d,--debug	debugging mode (LOTS of messages)
-h,--help	print this message
''' % __VERSION__)

def main():
	try:
		opts, servers = getopt.getopt(sys.argv[1:], "ahd", ["all", "help", "debug"])
	except getopt.GetoptError as e:
		logger.critical(str(e))
		usage()
		sys.exit(2)

	runall = False
	debug = False
 
	for o, a in opts:
		if o in ("-a", "--all"):
			runall = True
		elif o in  ("-d", "--debug"):
			debug = True
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		else:
			assert False, "unhandled option: %s" % o

	if debug: logger.setLevel(logging.DEBUG)
	if servers == [] and runall == False:
		logger.error("Please specify an APPP server to run, or use '-a' to run all servers! Exiting...")
		sys.exit(1)
	cfg = SafeConfigParser()
	cfg.optionxform = str
	runservers = {}
	try:
		cfg.readfp(open('APPP.ini'))
		if runall == True:
			logger.info("Attempting to run all APPP servers defined in APPP.ini")
			servers = list(cfg.sections())
		if servers == []: 
			logger.error("No APPP servers defined in APPP.ini! Exiting...")
			sys.exit(1)
		for srv in servers:
			if not cfg.has_section(srv):
				logger.error(srv + " is not defined in APPP.ini! Exiting...")
				continue
			server = config(cfg, srv)
			if not server:
				continue
			runservers[srv] = server
	except KeyboardInterrupt:
		logger.info("Shutting down...")
		sys.exit(0)
	except Exception as e:
		logger.critical(str(e))
		sys.exit(1)
	
	cfg = SafeConfigParser()
	cfg.optionxform = str
	try:
		logger.info("Read DNS.ini")
		
		cfg.readfp(open('DNS.ini'))
		
		for item in cfg.items("DNS"):
			items = item[1].split(',')
			i = 0
			while i < len(items):
				items[i] = (items[i].strip(), 5)
				
				i = i + 1
			dns[item[0]] = items
	except Exception as e:
		logger.info("Can not read DNS.ini" + str(e))
	
	if len(runservers) == 0:
		logger.critical("No runnable APPP server found! Exiting...")
		sys.exit(1)

	logger.info('Checking APPP certificates...')
	if not dump_ca(): sys.exit(1)
	logger.info('APPP certificates OK.')

	server_threads = {}
	for server in runservers:
		server_threads[server] = spawn(name=server, tgt=start_server, args=(runservers[server],))

	try:
		while not flag_exit:
			if activeCount() == 1:
				logger.info('No active APPP server running.')
				break
			sleep(5)
	except KeyboardInterrupt:
		pass
	logger.info("Shutting down...")
	sys.exit(0)

if __name__ == '__main__':
	main()

