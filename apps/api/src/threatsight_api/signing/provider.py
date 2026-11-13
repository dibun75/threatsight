"""Key-provider interface. Private key material never leaves the provider."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class PublicKeyMaterial:
    key_id: str
    algorithm: str
    public_key_pem: str
    fingerprint: str
    provider_type: str


def fingerprint_pem(public_pem: str) -> str:
    der = serialization.load_pem_public_key(public_pem.encode()).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


class KeyProvider(ABC):
    @abstractmethod
    def public_material(self) -> PublicKeyMaterial: ...

    @abstractmethod
    def sign(self, message: bytes) -> bytes: ...

    @abstractmethod
    def ready(self) -> tuple[bool, str]: ...


class FileEd25519Provider(KeyProvider):
    """Ed25519 private key loaded from a read-only file path. Never logs key bytes."""

    provider_type = "file_ed25519"
    algorithm = "Ed25519"

    def __init__(self, *, key_path: Path, key_id: str) -> None:
        self._key_path = key_path
        self._key_id = key_id
        self._private: Ed25519PrivateKey | None = None
        self._public_pem: str | None = None
        self._fingerprint: str | None = None
        self._error = "not_loaded"

    def load(self) -> None:
        path = self._key_path
        if not path.is_file():
            self._error = "missing_key"
            self._private = None
            return
        try:
            raw = path.read_bytes()
        except PermissionError:
            self._error = "invalid_permissions"
            self._private = None
            return
        except OSError:
            self._error = "unreadable_key"
            self._private = None
            return
        try:
            loaded = serialization.load_pem_private_key(raw, password=None)
        except Exception:
            self._error = "malformed_key"
            self._private = None
            return
        if not isinstance(loaded, Ed25519PrivateKey):
            self._error = "unsupported_algorithm"
            self._private = None
            return
        public = loaded.public_key()
        public_pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        self._private = loaded
        self._public_pem = public_pem
        self._fingerprint = fingerprint_pem(public_pem)
        self._error = ""

    def ready(self) -> tuple[bool, str]:
        if self._private is None:
            if self._error == "not_loaded":
                self.load()
            return (self._private is not None, self._error or "ok")
        return True, "ok"

    def public_material(self) -> PublicKeyMaterial:
        ok, reason = self.ready()
        if not ok or self._public_pem is None or self._fingerprint is None:
            raise RuntimeError(reason or "key_not_ready")
        return PublicKeyMaterial(
            key_id=self._key_id,
            algorithm=self.algorithm,
            public_key_pem=self._public_pem,
            fingerprint=self._fingerprint,
            provider_type=self.provider_type,
        )

    def sign(self, message: bytes) -> bytes:
        ok, reason = self.ready()
        if not ok or self._private is None:
            raise RuntimeError(reason or "key_not_ready")
        return self._private.sign(message)


def verify_ed25519(*, public_key_pem: str, message: bytes, signature: bytes) -> bool:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception:
        return False
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def generate_ed25519_keypair_files(*, private_path: Path, public_path: Path) -> str:
    """Write key files without returning or printing private key material. Returns fingerprint."""
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing key file")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(private_pem)
    private_path.chmod(0o400)
    public_path.write_bytes(public_pem)
    public_path.chmod(0o444)
    return fingerprint_pem(public_pem.decode())
