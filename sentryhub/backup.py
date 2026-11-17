"""Encrypted backups to AWS S3.

A backup is: all rows of the `users` table -> JSON -> gzip -> encrypted (Fernet, key derived
from BACKUP_PASSPHRASE with scrypt) -> uploaded to S3. Use scripts/decrypt_backup.py to read one.
"""
import base64
import gzip
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

from .formatting import fmt_dt

log = logging.getLogger(__name__)

MAGIC = b"SHB1"
SALT_LEN = 16
REQUIRED = ["BACKUP_S3_BUCKET", "BACKUP_AWS_ACCESS_KEY_ID", "BACKUP_AWS_SECRET_ACCESS_KEY", "BACKUP_PASSPHRASE"]


class BackupError(Exception):
    pass


def _fernet(passphrase, salt):
    from cryptography.fernet import Fernet

    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_blob(data, passphrase):
    salt = os.urandom(SALT_LEN)
    return MAGIC + salt + _fernet(passphrase, salt).encrypt(data)


def decrypt_blob(blob, passphrase):
    if not blob.startswith(MAGIC):
        raise BackupError("This is not a Sentry Hub backup file")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    return _fernet(passphrase, salt).decrypt(blob[len(MAGIC) + SALT_LEN:])


def export_snapshot(conn):
    return {
        "format": "sentry-hub-backup",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tables": {"users": conn.all("SELECT * FROM users ORDER BY id")},
    }


def make_s3_uploader(cfg):
    import boto3  # installed on Vercel via requirements.txt

    client = boto3.client(
        "s3",
        region_name=cfg["BACKUP_AWS_REGION"],
        aws_access_key_id=cfg["BACKUP_AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=cfg["BACKUP_AWS_SECRET_ACCESS_KEY"],
    )

    def upload(key, body):
        client.put_object(
            Bucket=cfg["BACKUP_S3_BUCKET"], Key=key, Body=body,
            ContentType="application/octet-stream", ServerSideEncryption="AES256",
        )

    return upload


def _record(conn, now, triggered_by, status, key, size, detail):
    conn.insert(
        "INSERT INTO backups (created_at, triggered_by, status, s3_key, size_bytes, detail) VALUES (%s, %s, %s, %s, %s, %s)",
        (now, triggered_by, status, key, size, detail),
    )
    ok = status == "success"
    return {
        "ok": ok,
        "message": "Backup successful" if ok else f"Backup failed: {detail}",
        "when": fmt_dt(now),
        "key": key,
    }


def run_backup(conn, cfg, triggered_by, uploader=None):
    now = int(time.time())
    needed = ["BACKUP_PASSPHRASE"] if uploader else REQUIRED
    missing = [name for name in needed if not cfg.get(name)]
    if missing:
        return _record(conn, now, triggered_by, "failed", None, None, "missing settings: " + ", ".join(missing))

    stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{cfg.get('BACKUP_S3_PREFIX', '')}sentry-hub-{stamp}.json.gz.enc"
    try:
        payload = json.dumps(export_snapshot(conn), separators=(",", ":")).encode("utf-8")
        blob = encrypt_blob(gzip.compress(payload), cfg["BACKUP_PASSPHRASE"])
        (uploader or make_s3_uploader(cfg))(key, blob)
    except Exception as exc:  # report any failure to the admin instead of crashing
        log.exception("Backup failed")
        return _record(conn, now, triggered_by, "failed", key, None, f"{type(exc).__name__}: {str(exc)[:200]}")
    return _record(conn, now, triggered_by, "success", key, len(blob), None)
