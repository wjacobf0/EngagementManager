"""Local configuration: data directory, SQLite path, and encryption key.

Designed for zero setup. On first run this creates a per-user data directory,
generates a Fernet key, and stores it with owner-only permissions. Nothing
needs to be exported or configured by hand.

Overrides (optional):
    EM_DATA_DIR   where the database and key live (default: see below)
    EM_DATABASE   full SQLAlchemy URL, overriding the default SQLite file
"""
import os
import stat
from functools import lru_cache
from pathlib import Path


def _default_data_dir() -> Path:
    # Respect XDG on Linux (Kali); fall back sensibly elsewhere.
    env = os.getenv("EM_DATA_DIR")
    if env:
        return Path(env).expanduser()
    xdg = os.getenv("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "engagement-manager"


class Config:
    def __init__(self) -> None:
        self.data_dir = _default_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.data_dir / "secret.key"
        self.db_path = self.data_dir / "engagement.db"

    @property
    def database_url(self) -> str:
        return os.getenv("EM_DATABASE") or f"sqlite:///{self.db_path}"

    def load_or_create_key(self) -> bytes:
        """Return the Fernet key, generating and persisting it on first use."""
        from cryptography.fernet import Fernet

        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        # Write with 0600 so other local users cannot read stored secrets.
        self.key_path.write_bytes(key)
        try:
            self.key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best effort on filesystems without POSIX perms
        return key


@lru_cache
def get_config() -> Config:
    return Config()
