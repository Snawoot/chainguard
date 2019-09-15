#!/usr/bin/env python3

import sys
import argparse
import sqlite3

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def parse_args():
    parser = argparse.ArgumentParser(
        description='Dump chain from chainguard database',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("db",
                        help="path to cert tracking database")
    parser.add_argument("chain_fp",
                        help="certificate chain fingerprint")
    return parser.parse_args()

query = """
    SELECT
        c.body 
    FROM
        chain_element e 
    LEFT JOIN
        certificate c 
            ON e.cert_fp = c.fp 
    WHERE
        e.chain_fp = ? AND c.body IS NOT NULL
    ORDER BY
        e.chain_position ASC 
"""

def main():
    args = parse_args()
    with sqlite3.connect(args.db) as conn:
        cur = conn.cursor()
        for row in cur.execute(query, (args.chain_fp,)):
            body = row[0]
            cert = x509.load_der_x509_certificate(body, default_backend())
            pem = cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
            sys.stdout.write(pem)


if __name__ == '__main__':  # pragma: no cover
    main()
