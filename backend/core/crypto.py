"""Secret wrapping + password-based backup encryption.

Two independent layers:

1. Secret wrapping (``wrap_secret``/``unwrap_secret``): at-rest protection for
   admin-entered secrets (backup encryption password, SMTP password) stored in
   MongoDB. Derived deterministically from SECRET_KEY so the server can unwrap
   them automatically for unattended cron jobs. This protects against casual
   DB reads; anyone with SECRET_KEY + DB access can still unwrap.

2. Password-based backup content encryption (``encrypt_backup_bytes``/
   ``decrypt_backup_bytes``): every encrypted backup file is self-contained -
   magic header + random salt + Fernet token - so import can auto-detect an
   encrypted upload vs. a plain legacy JSON export.
"""

import base64
import hashlib
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.config import SECRET_KEY

BACKUP_ENCRYPTION_MAGIC = b"RBBKENC1"
BACKUP_ENCRYPTION_PBKDF2_ITERATIONS = 390000


def _server_wrapping_fernet() -> Fernet:
    key_material = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key_material))


def wrap_secret(plaintext: str) -> str:
    return _server_wrapping_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def unwrap_secret(wrapped: str) -> Optional[str]:
    try:
        return _server_wrapping_fernet().decrypt(wrapped.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def _derive_backup_fernet(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=BACKUP_ENCRYPTION_PBKDF2_ITERATIONS)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8"))))


def encrypt_backup_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    token = _derive_backup_fernet(password, salt).encrypt(plaintext)
    return BACKUP_ENCRYPTION_MAGIC + salt + token


def is_encrypted_backup(blob: bytes) -> bool:
    return blob.startswith(BACKUP_ENCRYPTION_MAGIC)


def decrypt_backup_bytes(blob: bytes, password: str) -> bytes:
    if not is_encrypted_backup(blob):
        raise ValueError("Kein verschlüsseltes Backup-Format erkannt.")
    salt = blob[len(BACKUP_ENCRYPTION_MAGIC):len(BACKUP_ENCRYPTION_MAGIC) + 16]
    token = blob[len(BACKUP_ENCRYPTION_MAGIC) + 16:]
    try:
        return _derive_backup_fernet(password, salt).decrypt(token)
    except InvalidToken:
        raise ValueError("Falsches Backup-Passwort oder beschädigte Datei.")
