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
        description='Revise new certifications since given date',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("db",
                        help="path to cert tracking database")
    parser.add_argument("date",
                        help="lookup date in some human-readable format")
    return parser.parse_args()

query = """
SELECT
    group_concat(a.entity_name),
    a.issuer_fp,
    b.domain,
    b.ts,
    b.chain_fp,
    b.endpoint
FROM
    certification a
LEFT JOIN session b
ON a.discovered_session = b.id
WHERE
    b.ts >= ?
GROUP BY a.discovered_session
ORDER BY b.ts ASC
"""

def main():
    args = parse_args()
    since_dt = dateparser.parse(args.date)
    since_ts = since_dt.timestamp()
    with sqlite3.connect(args.db) as conn:
        cur = conn.cursor()
        for row in cur.execute(query, (since_ts,)):
            entity_name, issuer_fp, domain, ts, chain_fp, endpoint = row
            observed_dt_str = datetime.utcfromtimestamp(ts)\
                .replace(tzinfo=timezone.utc)\
                .astimezone(tz.tzlocal())\
                .isoformat()
            print("Names:", entity_name)
            print("Issuer Fingerprint (SHA256):", issuer_fp)
            print("Chain Fingerprint:", chain_fp)
            print("Observed at:", observed_dt_str)
            print("Endpoint:", endpoint)
            print("Domain:", domain)
            print("-----------------------------")


if __name__ == '__main__':  # pragma: no cover
    main()
