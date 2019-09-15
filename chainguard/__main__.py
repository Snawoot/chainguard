#!/usr/bin/env python3

import sys
import socket
import time
import datetime
import argparse
import sqlite3
import logging
from functools import partial

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from multiprocessing.dummy import Pool

from . import utils
from . import constants


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
        context = make_context()
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
                        default=3,
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
        "    chain_fp TEXT,\n"
        "    PRIMARY KEY (entity_name, issuer_fp))",
        "CREATE TABLE IF NOT EXISTS chain_element (\n"
        "    chain_fp TEXT,\n"
        "    chain_position INTEGER,\n"
        "    cert_fp TEXT,\n"
        "    PRIMARY KEY (chain_fp, chain_position))",
    ]
    cur = conn.cursor()
    for q in db_init:
        cur.execute(q)
    conn.commit()

def process_domain(chain, ts, conn):
    logger = logging.getLogger('PROCESSING')
    logger.debug("%s %s", chain, ts)

def main():
    args = parse_args()
    logger = utils.setup_logger('MAIN', args.verbosity)
    utils.setup_logger('PROCESSING', args.verbosity)
    pool = Pool(args.threads)
    logger.info("Starting patrol with %d workers to retrieve certs and "
                "db file %s", args.threads, repr(args.db))
    hostnames = (hostname for hostname in 
                 ( hostname.strip().rstrip('.') for hostname in sys.stdin ) if hostname)
    worker = partial(scan_worker, args.attempts, args.timeout)
    logger.debug("Opening DB connection...")
    with sqlite3.connect(args.db) as conn:
        setup_db(conn)
        logger.debug("DB connection setup finished.")
        for domain, result in pool.imap_unordered(worker, hostnames):
            logger.debug("Hostname %s returned result %s", repr(domain), repr(result))
            if result is None:
                logger.error("Failed to retrieve data from %s after %d attempts",
                             domain, args.attempts)
            else:
                chain, ts = result
                process_domain(chain, ts, conn)
    logger.info("Patrol finished.")


if __name__ == '__main__':  # pragma: no cover
    main()
