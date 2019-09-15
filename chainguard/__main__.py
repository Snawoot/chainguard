#!/usr/bin/env python3

import sys
import socket
import time
import datetime
import argparse
import sqlite3
from functools import partial

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from multiprocessing.dummy import Pool

from . import utils
from . import constants


#class ChainguardException(Exception):
#    pass
#
#
#class NoCertsReceived(ChainguardException):
#    def __init__(self):
#        pass
#
#    def __str__(self):
#        return "No certs retrieved!"
#
#
#class NoIntermediateCertReceived(ChainguardException):
#    def __init__(self, peer_cert=None):
#        self.peer_cert = peer_cert
#
#    def __str__(self):
#        return "No intermediate cert retrieved!"
#
#
#def make_context():
#    context = SSL.Context(method=SSL.TLSv1_2_METHOD)
#    return context
#
#
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


#def scan_host(hostname, port=443, timeout=5, context=None):
#    if context is None:
#        context = SSL.Context(method=SSL.TLSv1_2_METHOD)
#    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#    sock = SSL.Connection(context=context, socket=sock)
#    sock.set_tlsext_host_name(hostname.encode('ascii'))
#    sock.settimeout(timeout)
#    sock.connect((hostname, port))
#    sock.setblocking(1)
#    sock.do_handshake()
#
#    iter_certs = iter(sock.get_peer_cert_chain())
#    try:
#        peer_cert = next(iter_certs).to_cryptography()
#    except StopIteration:
#        raise NoCertsReceived()
#    try:
#        issuer_cert = next(iter_certs).to_cryptography()
#    except StopIteration:
#        raise NoIntermediateCertReceived(peer_cert.public_bytes(serialization.Encoding.PEM))
#    del iter_certs
#    sock.close()
#    del sock
#
#
#    names = get_x509_domains(peer_cert)
#    issuer = issuer_cert.fingerprint(SHA256()).hex()
#    return names, issuer
#
#
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
    ts = time.time()

    certs = [cert.to_cryptography() for cert in sock.get_peer_cert_chain()]
    sock.close()
    del sock
    return certs, ts


def scan_worker(attempts, timeout, domain):
    for _ in range(attempts):
        try:
            return domain, scan_host(domain, timeout=timeout)
        except Exception as exc:
            pass
    else:
        return (domain, None)


def parse_args():
    parser = argparse.ArgumentParser(
        description='TLS certificate chain watchdog which monitors hosts '
                    'for malicious certificates issued by rogue CA. Accepts'
                    ' input domains via STDIN, one per line.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("db",
                        help="path to cert tracking database")
    parser.add_argument("-v", "--verbosity",
                        help="logging verbosity",
                        type=utils.check_loglevel,
                        choices=constants.LogLevel,
                        default=constants.LogLevel.info)
    parser.add_argument("-n", "--threads",
                        type=utils.check_positive_int,
                        default=8,
                        help="number of threads to retrieve certs")
    parser.add_argument("-T", "--timeout",
                        type=utils.check_positive_float,
                        default=5.,
                        help="socket timeout in seconds")
    parser.add_argument("-t", "--attempts",
                        type=utils.check_positive_int,
                        default=1,
                        help="certificate fetch attempts per host")
    return parser.parse_args()

def setup_db(conn):
    db_init = [
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "CREATE TABLE IF NOT EXISTS certificate (fp TEXT PRIMARY KEY, body BLOB)",
        "CREATE TABLE IF NOT EXISTS certification (\n"
        "    entity_name TEXT,\n"
        "    issuer_fp TEXT,\n"
        "    observed_ts REAL,\n"
        "    chain_fp TEXT, PRIMARY KEY (entity_name, issuer_fp))",
        "CREATE TABLE IF NOT EXISTS chain_element (\n"
        "    chain_fp TEXT PRIMARY KEY,\n"
        "    chain_position INTEGER,\n"
        "    cert_fp TEXT)",
    ]
    cur = conn.cursor()
    for q in db_init:
        cur.execute(q)
    conn.commit()

def process_domain(chain, ts, conn):
    print(chain)

def main():
    args = parse_args()
    pool = Pool(args.threads)
    hostnames = (hostname for hostname in 
                 ( hostname.strip().rstrip('.') for hostname in sys.stdin ) if hostname)
    worker = partial(scan_worker, args.attempts, args.timeout)
    with sqlite3.connect(args.db) as conn:
        setup_db(conn)
        for domain, result in pool.imap_unordered(worker, hostnames):
            if result is not None:
                chain, ts = result
                process_domain(chain, ts, conn)
#    for hostname in hostnames:
#        try:
#            print(scan_host(hostname, context=context))
#        except NoIntermediateCertReceived as exc:
#            print("No intermediate cert received!")
#            print("Offending certificate:")
#            print(exc.peer_cert.decode('ascii'))
#        except Exception as exc:
#            print("Error: %s" % (str(exc),))


if __name__ == '__main__':  # pragma: no cover
    main()
