"""Encrypt captured secrets at rest with a locally stored Fernet key.

The key lives in the per-user data directory (see config.py) and is created
automatically on first run, so there is nothing to configure.
"""
from cryptography.fernet import Fernet, InvalidToken

from .config import get_config


def _fernet() -> Fernet:
    return Fernet(get_config().load_or_create_key())


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Could not decrypt secret (wrong or missing key)") from exc
