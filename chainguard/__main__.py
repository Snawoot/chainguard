#!/usr/bin/env python3

import sys
import argparse
import sqlite3
import logging
from functools import partial
from multiprocessing.dummy import Pool

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from . import utils
from . import constants
from .scanner import scan_host


crypto_backend = default_backend()


def sha256(data):
    digest = Hash(SHA256(), backend=crypto_backend)
    digest.update(data)
    return digest.finalize()


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
    if not chain:
        logger.error("Got empty cert chain!")
        return
    elif len(chain) == 1:
        logger.warn("Got certificate without issuer cert!")
    cur = conn.cursor()
    cur.execute("BEGIN TRANSACTION")

    # Prepare and insert certificates in chain
    fp_chain = []
    for cert in chain:
        cert_fp = cert.fingerprint(SHA256()).hex()
        fp_chain.append(cert_fp)
        cert_body = cert.public_bytes(serialization.Encoding.DER)
        try:
            cur.execute("INSERT INTO certificate (fp, body) VALUES (?, ?)",
                        (cert_fp, cert_body))
        except sqlite3.IntegrityError:
            pass

    chain_fp = sha256(','.join(fp_chain).encode('ascii')).hex()
    for idx, cert_fp in enumerate(fp_chain):
        try:
            cur.execute("INSERT INTO chain_element (chain_fp, chain_position, cert_fp)"
                        " VALUES (?, ?, ?)", (chain_fp, idx, cert_fp))
        except sqlite3.IntegrityError:
            pass

    do_commit = False
    for name in utils.get_x509_domains(chain[0]):
        issuer_fp = chain[1].fingerprint(SHA256()).hex() if len(chain) > 1 else None
        try:
            cur.execute("INSERT INTO certification (entity_name, issuer_fp, observed_ts, chain_fp)"
                        " VALUES (?, ?, ?, ?)", (name, issuer_fp, ts, chain_fp))
            do_commit = True
        except sqlite3.IntegrityError:
            pass
    if do_commit:
        cur.execute("COMMIT")
    else:
        cur.execute("ROLLBACK")
    cur.close()

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
