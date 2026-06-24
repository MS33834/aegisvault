"""Three-tier key hierarchy for AegisVault."""

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Key lengths (bytes) for derived keys.
VAULT_KEY_LEN = 32
FILE_KEY_LEN = 32


def derive_vault_key(master_key: bytes, info: bytes = b"vault-key-v1") -> bytes:
    """Derive Vault Key from Master Key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=VAULT_KEY_LEN,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def derive_file_key(vault_key: bytes, salt: bytes) -> bytes:
    """Derive File Key from Vault Key using Argon2id."""
    return hash_secret_raw(
        secret=vault_key,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=FILE_KEY_LEN,
        type=Type.ID,
    )


def generate_salt() -> bytes:
    """Generate a 32-byte random salt."""
    return os.urandom(32)
