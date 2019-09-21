import socket
import time
from functools import partial

from OpenSSL import SSL, crypto
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT

from .utils import get_x509_domains


def make_context(hostname):
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    context.set_default_verify_paths()
    context.set_verify(
        VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT,
        partial(verify_cb_prototype, hostname))
    return context


def verify_cb_prototype(hostname, conn, cert, errnum, depth, ok):
    if depth == 0:
        names = set(get_x509_domains(cert.to_cryptography()))
        return ok and ((hostname in names) or ('.'.join(["*"] + hostname.split('.')[1:])) in names)
    else:
        return ok


def scan_host(hostname, port=443, timeout=5, context=None):
    if context is None:
        context = make_context(hostname)
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
