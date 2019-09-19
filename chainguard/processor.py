import uuid
import sqlite3
import logging

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from . import utils


crypto_backend = default_backend()


def sha256(data):
    digest = Hash(SHA256(), backend=crypto_backend)
    digest.update(data)
    return digest.finalize()


class ChainProcessor(object):
    def __init__(self, dbfilename):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._dbfilename = dbfilename
        self._conn = None
        self._logger.debug("ChainProcessor constructed.")

    def prepare(self):
        conn = sqlite3.connect(self._dbfilename)
        db_init = [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "CREATE TABLE IF NOT EXISTS certificate (fp TEXT PRIMARY KEY, body BLOB)",
            "CREATE TABLE IF NOT EXISTS chain_element (\n"
            "    chain_fp TEXT,\n"
            "    chain_position INTEGER,\n"
            "    cert_fp TEXT,\n"
            "    PRIMARY KEY (chain_fp, chain_position))",
            "CREATE TABLE IF NOT EXISTS session (\n"
            "    id TEXT PRIMARY KEY,\n"
            "    domain TEXT,\n"
            "    ts REAL,\n"
            "    chain_fp TEXT,\n"
            "    endpoint TEXT\n"
            ")",
            "CREATE INDEX IF NOT EXISTS idx_session_ts\n"
            "ON session (ts)\n",
            "CREATE TABLE IF NOT EXISTS certification (\n"
            "    entity_name TEXT,\n"
            "    issuer_fp TEXT,\n"
            "    discovered_session TEXT,\n"
            "    PRIMARY KEY (entity_name, issuer_fp))",
        ]
        cur = conn.cursor()
        for q in db_init:
            cur.execute(q)
        conn.commit()
        cur.close()
        self._conn = conn
        self._logger.info("ChainProcessor initialized.")
        return self

    def shutdown(self):
        self._conn.close()

    def __enter__(self):
        return self.prepare()

    def __exit__(self, ext_type, exc_value, tb):
        return self.shutdown()

    def feed(self, domain, chain, ts, peer):
        peer_str = peer[0] + '#' + str(peer[-1])
        session_id = uuid.uuid4().hex
        self._logger.debug("%s %s", chain, ts)
        if not chain:
            self._logger.error("Got empty cert chain!")
            return
        elif len(chain) == 1:
            self._logger.warning("Got certificate without issuer cert! "
                                 "Certificate subject: %s",
                                 chain[0].subject.rfc4514_string())
        cur = self._conn.cursor()
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

        cur.execute("INSERT INTO session (id, domain, ts, chain_fp, endpoint) VALUES (?, ?, ?, ?, ?)",
                    (session_id, domain, ts, chain_fp, peer_str))
        names = utils.get_x509_domains(chain[0])
        do_commit = False
        for name in names:
            issuer_fp = chain[1].fingerprint(SHA256()).hex() if len(chain) > 1 else ''
            try:
                cur.execute("INSERT INTO certification (entity_name, issuer_fp, discovered_session)"
                            " VALUES (?, ?, ?)", (name, issuer_fp, session_id))
                do_commit = True
            except sqlite3.IntegrityError:
                pass
        if do_commit:
            cur.execute("COMMIT")
            self._logger.warning("New issuer %s detected in chain %s! Names affected: %s",
                                 issuer_fp, chain_fp, names)
        else:
            cur.execute("ROLLBACK")
        cur.close()
