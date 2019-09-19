import socket
import time
from OpenSSL import SSL, crypto


def make_context():
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    return context


def scan_host(hostname, port=443, timeout=5, context=None):
    if context is None:
        context = make_context()
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
