from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from conf import AES_KEY


def aes_encrypt(plaintext: str) -> str:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padded = plaintext.encode('utf-8').ljust(32, b'\0')  # zero-padding to 32 bytes
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext.hex()


def aes_decrypt(ciphertext_hex: str) -> str:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.rstrip(b'\0').decode('utf-8')