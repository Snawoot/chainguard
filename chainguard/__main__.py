#!/usr/bin/env python3

import sys
import socket
import datetime
from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


def make_context():
    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    return context


def get_x509_domains(cert):
    names = []

    try:
        alt_names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = alt_names.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        pass

    if not names:
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names:
            common_name = common_names[0]
            names = [common_name.value]
    return names


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
        print(' {0} Names:{1}'.format(' ', get_x509_domains(cert)))
    sock.close()


def main():
    context = make_context()
    for hostname in sys.stdin:
        if hostname:
            hostname = hostname.strip('.').strip()
            print_chain(context, hostname)


if __name__ == '__main__':  # pragma: no cover
    main()
