"""Decrypt a Sentry Hub backup downloaded from S3.

    python scripts/decrypt_backup.py sentry-hub-20261117T030000Z.json.gz.enc  [output.json]

You'll be asked for the BACKUP_PASSPHRASE (or set it in the BACKUP_PASSPHRASE environment variable).
"""
import getpass
import gzip
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentryhub.backup import decrypt_blob  # noqa: E402


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) > 2 else src.replace(".enc", "").replace(".gz", "") or "backup.json"
    passphrase = os.environ.get("BACKUP_PASSPHRASE") or getpass.getpass("Backup passphrase: ")
    with open(src, "rb") as fh:
        data = gzip.decompress(decrypt_blob(fh.read(), passphrase))
    with open(dest, "wb") as fh:
        fh.write(data)
    print(f"Decrypted to {dest} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
