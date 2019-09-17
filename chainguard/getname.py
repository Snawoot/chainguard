#!/usr/bin/env python3

import sys
import argparse
import sqlite3
from datetime import datetime
from datetime import timezone
from dateutil import tz

import dateparser

def parse_args():
    parser = argparse.ArgumentParser(
        description='Revise certifications for given name',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("db",
                        help="path to cert tracking database")
    parser.add_argument("-L", "--like",
                        action="store_true",
                        help="use SQL-like pattern matching for searching name")
    parser.add_argument("entity_name",
                        help="get certifications for given name")
    return parser.parse_args()

def main():
    args = parse_args()
    query = """
    SELECT
        entity_name,
        issuer_fp,
        observed_ts,
        chain_fp
    FROM
        certification
    WHERE
        entity_name """ + ("LIKE" if args.like else "=") + """ ?
    ORDER BY observed_ts ASC
    """
    with sqlite3.connect(args.db) as conn:
        cur = conn.cursor()
        for row in cur.execute(query, (args.entity_name,)):
            entity_name, issuer_fp, observed_ts, chain_fp = row
            observed_dt_str = datetime.utcfromtimestamp(observed_ts)\
                .replace(tzinfo=timezone.utc)\
                .astimezone(tz.tzlocal())\
                .isoformat()
            print("Entity:", entity_name)
            print("Issuer Fingerprint (SHA256):", issuer_fp)
            print("Chain Fingerprint:", chain_fp)
            print("Observed at:", observed_dt_str)
            print("-----------------------------")


if __name__ == '__main__':  # pragma: no cover
    main()
