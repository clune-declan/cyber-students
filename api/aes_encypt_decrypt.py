from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from conf import ENCRYPTION_KEY  

def encrypt_data(plaintext):
    """Encrypts data using AES-GCM (requires plaintext as bytes)."""
    
    iv = os.urandom(12)
   
    cipher = Cipher(
        algorithms.AES(ENCRYPTION_KEY),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
  
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
  
    return iv + encryptor.tag + ciphertext

def decrypt_data(ciphertext):
    """Decrypts AES-GCM encrypted data."""
    
    iv, tag, data = ciphertext[:12], ciphertext[12:28], ciphertext[28:]
  
    cipher = Cipher(
        algorithms.AES(ENCRYPTION_KEY),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
   
    return decryptor.update(data) + decryptor.finalize()


def encrypt_str(text):
    return encrypt_data(text).hex() 

def decrypt_str(hex_str):
    return decrypt_data(bytes.fromhex(hex_str)).decode()