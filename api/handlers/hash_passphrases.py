import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def hash_passphrase(passphrase, stored_salt=None):
    # Generate pepper on a per app basis
    pepper = os.urandom(16)
    
    # Generate salt on a per user basis if not provided
    if stored_salt is None:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(stored_salt)
    
    # Create KDF with combined salt and pepper
    kdf = Scrypt(
        salt=salt+pepper,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    
    # Convert passphrase to bytes and hash
    passphrase_bytes = bytes(passphrase, "utf-8")
    hashed_passphrase = kdf.derive(passphrase_bytes)
    
    return {
        'salt': salt.hex(),
        'hash': hashed_passphrase.hex(),
        'params': {
            'length': 32,
            'n': 2**14,
            'r': 8,
            'p': 1
        }
    }

def verify_passphrase(passphrase, stored_data):
    # Recreate the hash with same parameters
    result = hash_passphrase(passphrase, stored_data['salt'])
    # Compare the hashes
    return result['hash'] == stored_data['hash']

# Example usage
if __name__ == "__main__":
    # Get passphrase from user
    passphrase = input("Please enter your passphrase: ")
    
    # Hash the passphrase
    result = hash_passphrase(passphrase)
    
    # Print the results exactly as in the skeleton code
    print("Algorithm: Scrypt")
    print("Salt: " + result['salt'])
    print("Length: 32")
    print("n: 2**14")
    print("r: 8")
    print("p: 1")
    print("Hashed passphrase: " + result['hash'])