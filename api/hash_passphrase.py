from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def hash_passphrase(passphrase, salt, pepper):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + pepper,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())