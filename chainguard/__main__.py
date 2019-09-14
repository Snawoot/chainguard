#!/usr/bin/env python3

import sys
import socket
import datetime
from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


class ChainguardException(Exception):
    pass


class NoCertsReceived(ChainguardException):
    def __init__(self):
        pass

    def __str__(self):
        return "No certs retrieved!"


class NoIntermediateCertReceived(ChainguardException):
    def __init__(self, peer_cert=None):
        self.peer_cert = peer_cert

    def __str__(self):
        return "No intermediate cert retrieved!"


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


def scan_host(hostname, port=443, timeout=5, context=None):
    if context is None:
        context = SSL.Context(method=SSL.TLSv1_2_METHOD)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = SSL.Connection(context=context, socket=sock)
    sock.set_tlsext_host_name(hostname.encode('ascii'))
    sock.settimeout(timeout)
    sock.connect((hostname, port))
    sock.setblocking(1)
    sock.do_handshake()

    iter_certs = iter(sock.get_peer_cert_chain())
    try:
        peer_cert = next(iter_certs).to_cryptography()
    except StopIteration:
        raise NoCertsReceived()
    try:
        issuer_cert = next(iter_certs).to_cryptography()
    except StopIteration:
        raise NoIntermediateCertReceived(peer_cert.public_bytes(serialization.Encoding.PEM))
    del iter_certs
    sock.close()
    del sock


    names = get_x509_domains(peer_cert)
    issuer = issuer_cert.fingerprint(SHA256()).hex()
    print(issuer_cert.subject)
    return names, issuer


def main():
    context = make_context()
    for hostname in sys.stdin:
        hostname = hostname.strip()
        if hostname:
            hostname = hostname.strip('.').strip()
            try:
                print(scan_host(hostname, context=context))
            except NoIntermediateCertReceived as exc:
                print("No intermediate cert received!")
                print("Offending certificate:")
                print(exc.peer_cert.decode('ascii'))


if __name__ == '__main__':  # pragma: no cover
    main()
