import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from conf import APP_PEPPER


def hash_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt + APP_PEPPER,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    kdf = Scrypt(
        salt=salt + APP_PEPPER,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), expected_hash)
        return True
    except Exception:
        return False