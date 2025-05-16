from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from ..conf import AES_KEY

class AESCipher:
    def __init__(self):
        # Derive a 256-bit key from the configuration key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=b'static_salt_123',  # Using a static salt since we want the same key each time
            iterations=1,  # Single iteration since we just need key stretching
            backend=default_backend()
        )
        self.key = kdf.derive(AES_KEY)
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
        
        # Return IV + ciphertext as hex
        return (iv + ciphertext).hex()

    def decrypt(self, hex_data):
        if not hex_data:
            return ''
            
        # Convert from hex to bytes
        data = bytes.fromhex(hex_data)
        
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

# Create singleton instance
aes = AESCipher()

# Main interface functions that return hex strings
def aes_encrypt(plaintext):
    """Encrypt data and return as hex string"""
    if not plaintext:
        return ''
    return aes.encrypt(plaintext)

def aes_decrypt(hex_data):
    """Decrypt data from hex string"""
    if not hex_data:
        return ''
    return aes.decrypt(hex_data)

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