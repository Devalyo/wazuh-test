"""Shared-secret Fernet helpers for the Mini Wazuh cluster lab."""

from base64 import urlsafe_b64encode
from hashlib import sha256

from cryptography.fernet import Fernet


DEFAULT_CLUSTER_SECRET = "mini-wazuh-local-simulator"


def derive_fernet_key(secret: str) -> bytes:
    """Derive a deterministic Fernet key from a non-empty cluster secret."""
    if not secret:
        raise ValueError("cluster secret must not be empty")
    return urlsafe_b64encode(sha256(secret.encode("utf-8")).digest())


def build_fernet(secret: str) -> Fernet:
    """Build a Fernet instance using the deterministic cluster key."""
    return Fernet(derive_fernet_key(secret))
