#!/usr/bin/env python3

import sys
import socket
import datetime
from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.hashes import SHA256

def make_context():
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    return context

def print_chain(context, hostname, timeout=5):
    print('Getting certificate chain for {0}'.format(hostname))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SSL.Connection(context=context, socket=sock)
    sock.set_tlsext_host_name(hostname.encode('ascii'))
    sock.settimeout(timeout)
    sock.connect((hostname, 443))
    sock.setblocking(1)
    sock.do_handshake()
    for (idx, cert) in enumerate(sock.get_peer_cert_chain()):
        cert = cert.to_cryptography()
        print(' {0} s:{1}'.format(idx, cert.subject.rfc4514_string()))
        print(' {0} i:{1}'.format(' ', cert.issuer.rfc4514_string()))
        print(' {0} fp(SHA256)={1}'.format(' ', cert.fingerprint(SHA256()).hex()))
        #print(' {0} SAN:{1}'.format(' ', parse_x509_san(cert)))
    sock.close()

def main():
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


if __name__ == '__main__':  # pragma: no cover
    main()
