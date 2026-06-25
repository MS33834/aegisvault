"""Device authorization and revocation management for AegisVault sync.

Manages device pairing, shared-secret key exchange, and revocation.
Implements a simplified PAKE-style protocol:

1. Device A generates a 6-digit pairing code (5-minute expiry) and an
   ephemeral X25519 key pair.  The code is shown to the user.
2. The user enters the code manually on Device B.
3. Device B generates its own ephemeral X25519 key pair and sends its
   public key to Device A (along with the pairing code for verification).
4. Both devices derive a 32-byte shared secret via HKDF-SHA256:
   ``HKDF(ikm=DH_shared, salt=pairing_code, info=b"aegisvault-pairing-v1")``
5. Each device stores the shared secret encrypted at rest (via
   ``secure_storage.seal``).

Design notes
------------
- Every pairing session uses fresh ephemeral keys → forward secrecy.
- The pairing code acts as HKDF salt, binding the resulting key to the
  out-of-band code exchange.
- Shared secrets are sealed with :func:`aegisvault.platform.secure_storage.seal`
  before persisting to `config_dir / "devices.json"`.
- Max 5 paired devices (``MAX_PAIRED_DEVICES``).
"""

import json
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

PAIRING_CODE_DIGITS = 6
PAIRING_CODE_TTL = 300  # seconds (5 minutes)
MAX_PAIRED_DEVICES = 5
HKDF_INFO_PAIRING = b"aegisvault-pairing-v1"
HKDF_LENGTH = 32

# ── Type aliases (lazy – avoids import-time overhead) ────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    _X25519PrivateKeyType = X25519PrivateKey
    _X25519PublicKeyType = X25519PublicKey
except ImportError:  # pragma: no cover
    _X25519PrivateKeyType = Any  # type: ignore[assignment]
    _X25519PublicKeyType = Any  # type: ignore[assignment]


# ── Ephemeral pairing session (in-memory only) ───────────────────────────────


@dataclass
class PairingSession:
    """In-memory state for an active pairing session."""

    code: str
    expires_at: float
    private_key: "_X25519PrivateKeyType"
    public_key: "_X25519PublicKeyType"


# ── Persisted device record ──────────────────────────────────────────────────


@dataclass
class DeviceRecord:
    """Persisted record of an authorized peer device."""

    device_id: str
    device_name: str
    created_at: float = 0.0
    last_seen: float = 0.0
    sealed_secret: str = ""  # sealed via secure_storage.seal


# ── Device auth manager ──────────────────────────────────────────────────────


class DeviceAuth:
    """Manage device pairing, authorization, and revocation.

    Parameters
    ----------
    config_dir:
        Directory where ``devices.json`` is stored.  Created if missing.
    """

    def __init__(self, config_dir: Path) -> None:
        self._config_dir = config_dir
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._devices_path = config_dir / "devices.json"
        self._devices: dict[str, DeviceRecord] = {}
        self._pending_pairing: PairingSession | None = None
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_pairing_code(self) -> str:
        """Generate a 6-digit numeric pairing code valid for 5 minutes.

        Also creates an ephemeral X25519 key pair for the pending session.
        The public key can be retrieved via :meth:`get_pending_public_key`
        for transmission to the peer device.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        code = format(secrets.randbelow(10**PAIRING_CODE_DIGITS), f"0{PAIRING_CODE_DIGITS}d")
        private = X25519PrivateKey.generate()
        public = private.public_key()

        self._pending_pairing = PairingSession(
            code=code,
            expires_at=time.time() + PAIRING_CODE_TTL,
            private_key=private,
            public_key=public,
        )
        logger.info("Pairing code generated (valid for %ds)", PAIRING_CODE_TTL)
        return code

    def pair_device(self, device_name: str, pairing_code: str, peer_public_key_bytes: bytes) -> str:
        """Complete device pairing as the initiator (code generator).

        Verifies the pairing code, performs X25519 key exchange with the
        peer's public key, and stores the resulting shared secret.

        Parameters
        ----------
        device_name:
            Human-readable name for the paired device.
        pairing_code:
            The 6-digit code the peer entered (must match the pending session).
        peer_public_key_bytes:
            Raw 32-byte X25519 public key from the peer device.

        Returns
        -------
        A new *device_id* (32 hex chars) for the paired device.

        Raises
        ------
        RuntimeError:
            If no pending pairing session exists, the code is wrong, expired,
            or the maximum device count is reached.
        """
        if self._pending_pairing is None:
            raise RuntimeError("No pending pairing session; call generate_pairing_code() first")
        if time.time() > self._pending_pairing.expires_at:
            self._pending_pairing = None
            raise RuntimeError("Pairing code expired")
        if not pairing_code or pairing_code != self._pending_pairing.code:
            raise RuntimeError("Pairing code mismatch")

        if len(self._devices) >= MAX_PAIRED_DEVICES:
            raise RuntimeError(f"Maximum paired devices ({MAX_PAIRED_DEVICES}) reached")

        our_private = self._pending_pairing.private_key
        peer_public = _x25519_public_from_bytes(peer_public_key_bytes)

        shared_secret = _derive_shared_secret(our_private, peer_public, pairing_code)
        device_id = str(secrets.token_hex(16))

        record = self._make_record(device_id, device_name, shared_secret)
        self._devices[device_id] = record
        self._pending_pairing = None
        self._save()

        logger.info("Device paired: %s (%s)", device_name, device_id)
        return device_id

    def accept_pairing(
        self,
        pairing_code: str,
        initiator_public_key_bytes: bytes,
        device_name: str,
    ) -> tuple[str, bytes]:
        """Complete device pairing as the responder (code receiver).

        Generates our own ephemeral X25519 key pair, derives the shared secret,
        and returns the new device ID and our public key (for the initiator).

        Parameters
        ----------
        pairing_code:
            The 6-digit code displayed on the initiator's screen.
        initiator_public_key_bytes:
            Raw 32-byte X25519 public key from the initiator.
        device_name:
            Human-readable name for this device.

        Returns
        -------
        A tuple of ``(device_id, our_public_key_bytes)``.

        Raises
        ------
        RuntimeError:
            If the maximum device count is reached.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        if len(self._devices) >= MAX_PAIRED_DEVICES:
            raise RuntimeError(f"Maximum paired devices ({MAX_PAIRED_DEVICES}) reached")

        our_private = X25519PrivateKey.generate()
        our_public = our_private.public_key()
        peer_public = _x25519_public_from_bytes(initiator_public_key_bytes)

        shared_secret = _derive_shared_secret(our_private, peer_public, pairing_code)
        device_id = str(secrets.token_hex(16))

        record = self._make_record(device_id, device_name, shared_secret)
        self._devices[device_id] = record
        self._save()

        our_public_bytes = _x25519_public_to_bytes(our_public)
        logger.info("Device paired (responder): %s (%s)", device_name, device_id)
        return device_id, our_public_bytes

    def get_pending_public_key(self) -> bytes | None:
        """Return the pending session's X25519 public key bytes, or ``None``.

        Expired sessions are automatically cleared.
        """
        if self._pending_pairing is None:
            return None
        if time.time() > self._pending_pairing.expires_at:
            self._pending_pairing = None
            return None
        return _x25519_public_to_bytes(self._pending_pairing.public_key)

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def is_authorized(self, device_id: str) -> bool:
        """Return ``True`` if *device_id* is authorized."""
        return device_id in self._devices

    def revoke_device(self, device_id: str) -> None:
        """Revoke authorization for *device_id*.

        Raises ``KeyError`` if the device is not found.
        """
        if device_id not in self._devices:
            raise KeyError(f"Device not found: {device_id}")
        name = self._devices[device_id].device_name
        del self._devices[device_id]
        self._save()
        logger.info("Device revoked: %s (%s)", name, device_id)

    def list_authorized_devices(self) -> list[dict[str, Any]]:
        """Return metadata for all authorized devices."""
        return [
            {
                "device_id": r.device_id,
                "device_name": r.device_name,
                "created_at": r.created_at,
                "last_seen": r.last_seen,
            }
            for r in self._devices.values()
        ]

    def get_shared_secret(self, device_id: str) -> bytes | None:
        """Return the unsealed shared secret for *device_id*, or ``None``."""
        record = self._devices.get(device_id)
        if record is None or not record.sealed_secret:
            return None

        from aegisvault.platform.secure_storage import unseal

        hex_secret = unseal(record.sealed_secret)
        return bytes.fromhex(hex_secret)

    def touch_device(self, device_id: str) -> None:
        """Update the last-seen timestamp for *device_id*."""
        record = self._devices.get(device_id)
        if record:
            record.last_seen = time.time()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _make_record(self, device_id: str, device_name: str, shared_secret: bytes) -> DeviceRecord:
        from aegisvault.platform.secure_storage import seal

        return DeviceRecord(
            device_id=device_id,
            device_name=device_name,
            created_at=time.time(),
            last_seen=time.time(),
            sealed_secret=seal(shared_secret.hex()),
        )

    def _load(self) -> None:
        """Load device records from disk."""
        if not self._devices_path.exists():
            return
        try:
            raw = json.loads(self._devices_path.read_text(encoding="utf-8"))
            for entry in raw:
                record = DeviceRecord(
                    device_id=entry["device_id"],
                    device_name=entry["device_name"],
                    created_at=entry.get("created_at", 0.0),
                    last_seen=entry.get("last_seen", 0.0),
                    sealed_secret=entry.get("sealed_secret", ""),
                )
                self._devices[record.device_id] = record
        except (json.JSONDecodeError, KeyError, OSError):
            logger.warning("Failed to load devices.json; starting with empty device list")

    def _save(self) -> None:
        """Persist device records to disk atomically.

        Merges in-memory records with any existing on-disk records so that
        multiple :class:`DeviceAuth` instances sharing the same config file
        do not silently clobber each other.
        """
        merged: dict[str, dict[str, Any]] = {}
        if self._devices_path.exists():
            try:
                raw = json.loads(self._devices_path.read_text(encoding="utf-8"))
                for entry in raw:
                    merged[entry["device_id"]] = entry
            except (json.JSONDecodeError, KeyError, OSError):
                pass

        for r in self._devices.values():
            merged[r.device_id] = {
                "device_id": r.device_id,
                "device_name": r.device_name,
                "created_at": r.created_at,
                "last_seen": r.last_seen,
                "sealed_secret": r.sealed_secret,
            }

        data = sorted(merged.values(), key=lambda d: d["device_id"])
        content = json.dumps(data, indent=2)
        tmp = self._devices_path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(self._devices_path)


# ── Crypto helpers ───────────────────────────────────────────────────────────


def _derive_shared_secret(
    our_private: "_X25519PrivateKeyType",
    peer_public: "_X25519PublicKeyType",
    pairing_code: str,
) -> bytes:
    """Derive a 32-byte shared secret from DH exchange + pairing code.

    Uses HKDF-SHA256 with the X25519 shared key as IKM and the pairing
    code as salt.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    shared_key = our_private.exchange(peer_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_LENGTH,
        salt=pairing_code.encode("utf-8"),
        info=HKDF_INFO_PAIRING,
    )
    return hkdf.derive(shared_key)


def _x25519_public_to_bytes(key: "_X25519PublicKeyType") -> bytes:
    """Serialize X25519 public key to 32 raw bytes."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _x25519_public_from_bytes(raw: bytes) -> "_X25519PublicKeyType":
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    return X25519PublicKey.from_public_bytes(raw)
