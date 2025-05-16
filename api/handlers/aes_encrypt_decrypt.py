from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# setup the key
key = "thebestsecretkey"
key_bytes = bytes(key, "utf-8")

# make the cipher
aes_cipher = Cipher(
    algorithms.AES(key_bytes),
    modes.ECB(),
    backend=default_backend()
)

# create encryptor and decryptor objects that can be imported
aes_encryptor = aes_cipher.encryptor()
aes_decryptor = aes_cipher.decryptor()

def encrypt_stuff(plaintext):
    # convert text to bytes and encrypt it
    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_encryptor.update(plaintext_bytes) + aes_encryptor.finalize()
    
    # convert to hex for storage
    return ciphertext_bytes.hex()

def decrypt_stuff(ciphertext):
    # convert hex back to bytes and decrypt
    ciphertext_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes = aes_decryptor.update(ciphertext_bytes) + aes_decryptor.finalize()
    
    # convert back to text
    return str(plaintext_bytes, "utf-8")

# test it works
if __name__ == "__main__":
    # setup test data
    print("Key: " + key)
    
    plaintext = "thebestplaintext"
    print("Plaintext: " + plaintext)
    
    # encrypt it
    ciphertext = encrypt_stuff(plaintext)
    print("Ciphertext: " + ciphertext)
    
    # decrypt it
    plaintext_2 = decrypt_stuff(ciphertext)
    print("Original Plaintext: " + plaintext_2)