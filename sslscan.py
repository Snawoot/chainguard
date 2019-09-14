#!/usr/bin/env python3

import sys
import socket
import datetime
from OpenSSL import SSL, crypto


def make_context():
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    return context

def print_chain(context, hostname):
    print('Getting certificate chain for {0}'.format(hostname))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SSL.Connection(context=context, socket=sock)
    sock.set_tlsext_host_name(hostname.encode('ascii'))
    sock.settimeout(5)
    sock.connect((hostname, 443))
    sock.setblocking(1)
    sock.do_handshake()
    notafter = sock.get_peer_certificate().get_notAfter()
    utcafter = datetime.datetime.strptime(notafter.decode('ascii'), "%Y%m%d%H%M%SZ")
    utcnow = datetime.datetime.utcnow()
    print(' 0 e: {0} [{1}]'.format(utcafter - utcnow, notafter))
    for (idx, cert) in enumerate(sock.get_peer_cert_chain()):
        print(' {0} s:{1}'.format(idx, cert.get_subject()))
        print(' {0} i:{1}'.format(' ', cert.get_issuer()))
    sock.close()

context = make_context()
for hostname in sys.stdin:
    if hostname:
        hostname = hostname.strip('.').strip()
        try:
            hostname.index('.')
            print_chain(context, hostname)
        except Exception as e:
            print('   f:{0}'.format(str(e)))
            try:
                hostname = 'www.'+hostname
                print_chain(context, hostname)
            except:
                print('   f:{0}'.format(str(e)))
