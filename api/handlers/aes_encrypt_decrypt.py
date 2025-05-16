from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from ..conf import AES_KEY

def get_encryption_key():
   
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=b'static_salt_123', key each time
        iterations=1,  
        backend=default_backend()
    )
    return kdf.derive(AES_KEY)

def pad(data):
    """PKCS7 padding implementation"""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    """PKCS7 unpadding implementation"""
    padding_length = data[-1]
    return data[:-padding_length]

def aes_encrypt(plaintext):
    """Encrypt data and return as hex string"""
    if not plaintext:
        return ''

    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

  
    iv = os.urandom(16)

    
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    
    padded_data = pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

  
    return (iv + ciphertext).hex()

def aes_decrypt(hex_data):
    """Decrypt data from hex string"""
    if not hex_data:
        return ''

   
    data = bytes.fromhex(hex_data)

    
    iv = data[:16]
    ciphertext = data[16:]

   
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

   
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted = unpad(decrypted_padded)

    
    return decrypted.decode('utf-8')


if __name__ == "__main__":
    test_data = "Test, Test, "
    print(f"Original: {test_data}")
    
    
    encrypted = aes_encrypt(test_data)
    print(f"Encrypted (hex): {encrypted}")
    
    
    decrypted = aes_decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
  
    print(f"Empty string test - Encrypted: {aes_encrypt('')}")
    print(f"Empty string test - Decrypted: {aes_decrypt('')}")
    
    