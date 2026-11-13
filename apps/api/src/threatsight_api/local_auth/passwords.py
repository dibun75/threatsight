"""Argon2id passwords. Submitted passwords are never logged."""

from __future__ import annotations

import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

MIN_LENGTH = 15
MAX_LENGTH = 128
# OWASP Argon2id baseline: 19 MiB, two iterations, one lane.
HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)
_DUMMY = HASHER.hash("not-a-user-password")
_BLOCKLIST = frozenset(
    {
        "passwordpassword",
        "correcthorsebatterystaple",
        "threatsightpassword",
        "changemechangeme",
        "administratoradmin",
        "qwertyuiopasdfgh",
        "letmeinletmein1",
        "welcomewelcome1",
        "passw0rdpassw0rd",
        "iloveyouiloveyou",
    }
)


class PasswordRejected(ValueError):
    pass


def validate_password(password: str) -> None:
    if not isinstance(password, str) or not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        raise PasswordRejected("password rejected")
    folded = password.casefold().strip()
    if folded in _BLOCKLIST or password.casefold() in _BLOCKLIST:
        raise PasswordRejected("password rejected")


def hash_password(password: str) -> str:
    validate_password(password)
    return HASHER.hash(password)


def verify_password(password: str, encoded: str | None) -> bool:
    target = encoded or _DUMMY
    try:
        HASHER.verify(target, password)
        return encoded is not None
    except VerifyMismatchError:
        return False


def needs_rehash(encoded: str) -> bool:
    return HASHER.check_needs_rehash(encoded)


def benchmark_milliseconds() -> int:
    started = time.perf_counter()
    HASHER.hash("benchmark-password-value")
    return int((time.perf_counter() - started) * 1000)
