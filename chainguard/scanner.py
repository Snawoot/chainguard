import socket
import time
from functools import partial

from OpenSSL import SSL, crypto
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT

from .utils import get_x509_domains


def make_context(verify_cb):
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    context.set_default_verify_paths()
    context.set_verify(
        VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_cb)
    return context


class ChainVerifier:
    def __init__(self, hostname):
        self._hostname = hostname.lower()

    def verify_cb(self, conn, cert, errnum, depth, ok):
        if depth == 0:
            if not ok:
                # Skip further steps if preverify failed
                return False
            names = set(name.rstrip('.').lower() for name in get_x509_domains(cert.to_cryptography()))
            if self._hostname in names:
                return True
            wildcard = '.'.join(["*"] + self._hostname.split('.')[1:])
            return wildcard in names
        else:
            return bool(ok)


def scan_host(hostname, port=443, timeout=5):
    verifier = ChainVerifier(hostname)
    context = make_context(verifier.verify_cb)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SSL.Connection(context=context, socket=sock)
    sock.set_tlsext_host_name(hostname.encode('ascii'))
    sock.settimeout(timeout)
    sock.connect((hostname, port))
    sock.setblocking(1)
    sock.do_handshake()
    ts = time.time()
    peer = None
    try:
        peer = sock.getpeername()
    except:
        pass

    certs = [cert.to_cryptography() for cert in sock.get_peer_cert_chain()]
    sock.close()
    del sock
    return certs, ts, peer
