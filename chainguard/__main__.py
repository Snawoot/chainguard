#!/usr/bin/env python3

import sys
import argparse
import logging
from functools import partial
from multiprocessing.dummy import Pool

from . import utils
from . import constants
from .scanner import scan_host
from .processor import ChainProcessor


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
                        default=constants.LogLevel.warn)
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

def main():
    args = parse_args()
    logger = utils.setup_logger('MAIN', args.verbosity)
    utils.setup_logger(ChainProcessor.__name__, args.verbosity)

    logger.info("Starting patrol with %d workers to retrieve certs and "
                "db file %s", args.threads, repr(args.db))
    pool = Pool(args.threads)
    hostnames = (hostname for hostname in 
                 ( hostname.strip().rstrip('.') for hostname in sys.stdin ) if hostname)
    worker = partial(scan_worker, args.attempts, args.timeout)
    with ChainProcessor(args.db) as processor:
        for domain, result in pool.imap_unordered(worker, hostnames):
            logger.debug("Hostname %s returned result %s", repr(domain), repr(result))
            if result is None:
                logger.error("Failed to retrieve data from %s after %d attempts",
                             domain, args.attempts)
            else:
                chain, ts = result
                processor.feed(chain, ts)
    logger.info("Patrol finished.")


if __name__ == '__main__':  # pragma: no cover
    main()
