from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from ..conf import AES_KEY

def get_encryption_key():
    # Derive a 256-bit key from the configuration key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=b'static_salt_123',  # Using a static salt since we want the same key each time
        iterations=1,  # Single iteration since we just need key stretching
        backend=default_backend()
    )
    return kdf.derive(AES_KEY)

def aes_encrypt(plaintext):
    """Encrypt data and return as hex string"""
    if not plaintext:
        return ''

    # Convert to bytes if string
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    # Generate IV
    iv = os.urandom(16)

    # Create cipher
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Create padder and encryptor
    padder = padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()

    # Pad the data
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine IV and ciphertext and convert to hex
    return (iv + ciphertext).hex()

def aes_decrypt(hex_data):
    """Decrypt data from hex string"""
    if not hex_data:
        return ''

    # Convert from hex to bytes
    data = bytes.fromhex(hex_data)

    # Extract IV (first 16 bytes)
    iv = data[:16]
    ciphertext = data[16:]

    # Create cipher
    cipher = Cipher(
        algorithms.AES(get_encryption_key()),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Create unpadder and decryptor
    unpadder = padding.PKCS7(128).unpadder()
    decryptor = cipher.decryptor()

    # Decrypt
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    # Convert back to string
    return decrypted.decode('utf-8')

# Test the encryption
if __name__ == "__main__":
    test_data = "Hello, World!"
    print(f"Original: {test_data}")
    
    # Test encryption
    encrypted = aes_encrypt(test_data)
    print(f"Encrypted (hex): {encrypted}")
    
    # Test decryption
    decrypted = aes_decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Test empty string
    print(f"Empty string test - Encrypted: {aes_encrypt('')}")
    print(f"Empty string test - Decrypted: {aes_decrypt('')}")
    
    # Test multiple encryptions
    print("\nTesting multiple encryptions:")
    for i in range(3):
        text = f"Test {i}"
        enc = aes_encrypt(text)
        dec = aes_decrypt(enc)
        print(f"Original: {text}")
        print(f"Encrypted: {enc}")
        print(f"Decrypted: {dec}")
        print()