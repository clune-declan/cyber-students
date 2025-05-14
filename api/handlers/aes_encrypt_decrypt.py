from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(plaintext):
    # Initialize with the same key
    key = "thebestsecretkey"
    key_bytes = bytes(key, "utf-8")
    
    # Create cipher with ECB mode
    aes_cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Create encryptor
    aes_encryptor = aes_cipher.encryptor()
    
    # Convert plaintext to bytes and encrypt
    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_encryptor.update(plaintext_bytes) + aes_encryptor.finalize()
    
    # Convert to hex for storage
    return ciphertext_bytes.hex()

def decrypt_data(ciphertext):
    if not ciphertext:
        return None
        
    # Initialize with the same key
    key = "thebestsecretkey"
    key_bytes = bytes(key, "utf-8")
    
    # Create cipher with ECB mode
    aes_cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Create decryptor
    aes_decryptor = aes_cipher.decryptor()
    
    # Convert hex to bytes and decrypt
    ciphertext_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes = aes_decryptor.update(ciphertext_bytes) + aes_decryptor.finalize()
    
    # Convert back to string
    return str(plaintext_bytes, "utf-8")

# Example usage
if __name__ == "__main__":
    # Demonstrate encryption
    key = "thebestsecretkey"
    print("Key: " + key)
    
    plaintext = "thebestplaintext"
    print("Plaintext: " + plaintext)
    
    # Encrypt
    ciphertext = encrypt_data(plaintext)
    print("Ciphertext: " + ciphertext)
    
    # Decrypt
    plaintext_2 = decrypt_data(ciphertext)