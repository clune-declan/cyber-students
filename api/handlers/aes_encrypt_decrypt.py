from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from ..conf import AES_KEY

class AESCipher:
    def __init__(self):
        self.key = AES_KEY
        self.backend = default_backend()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def create_cipher(self, iv=None):
        if iv is None:
            iv = os.urandom(16)  # Generate a random 16-byte IV
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=self.backend
        )
        return cipher, iv

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Pad the data
        padded_data = self.padder.update(data) + self.padder.finalize()
        
        # Create cipher and get IV
        cipher, iv = self.create_cipher()
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext

    def decrypt(self, data):
        # Extract IV from the first 16 bytes
        iv = data[:16]
        ciphertext = data[16:]
        
        # Create cipher with the extracted IV
        cipher, _ = self.create_cipher(iv)
        decryptor = cipher.decryptor()
        
        # Decrypt and unpad
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted = self.unpadder.update(decrypted_padded) + self.unpadder.finalize()
        
        return decrypted.decode('utf-8')

# Create singleton instances for the handlers to use
aes = AESCipher()

def encrypt_to_hex(plaintext):
    """Encrypt data and return as hex string"""
    encrypted = aes.encrypt(plaintext)
    return encrypted.hex()

def decrypt_from_hex(hex_data):
    """Decrypt data from hex string"""
    encrypted = bytes.fromhex(hex_data)
    return aes.decrypt(encrypted)

# For backwards compatibility
aes_encryptor = aes.encrypt
aes_decryptor = aes.decrypt

# Test the encryption
if __name__ == "__main__":
    test_data = "Hello, World!"
    print(f"Original: {test_data}")
    
    # Test using hex functions
    encrypted_hex = encrypt_to_hex(test_data)
    print(f"Encrypted (hex): {encrypted_hex}")
    decrypted = decrypt_from_hex(encrypted_hex)
    print(f"Decrypted: {decrypted}")
    
    # Test using direct functions
    encrypted = aes_encryptor(test_data)
    print(f"Encrypted (bytes): {encrypted.hex()}")
    decrypted = aes_decryptor(encrypted)
    print(f"Decrypted: {decrypted}")