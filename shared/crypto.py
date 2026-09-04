"""Shared cryptographic utilities."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def file_hash(path: Path) -> dict[str, str]:
    """Compute multiple hashes for a file."""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)
            sha1_hash.update(chunk)

    return {
        "sha256": sha256_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
    }


def generate_secret(length: int = 64) -> str:
    return secrets.token_urlsafe(length)
