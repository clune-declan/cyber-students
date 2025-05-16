"""Password hashing module using Scrypt with per-app pepper and per-user salt."""
import os
from typing import Dict, Union
from cryptography.hazmat.primitives.kdf import scrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Application-wide pepper - should be generated once and stored securely
PEPPER: bytes = os.urandom(16)

def hash_my_password(passphrase: str) -> Dict[str, str]:
    """Hash a password using Scrypt with a unique salt and application pepper.
    
    Args:
        passphrase: The password to hash
        
    Returns:
        Dict containing the hex-encoded salt and hash
    """
    # Generate a unique salt for this user
    salt: bytes = os.urandom(16)
    
    # Create KDF instance with salt+pepper
    kdf = Scrypt(
        salt=salt + PEPPER,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    
    # Convert password to bytes and hash it
    passphrase_bytes: bytes = bytes(passphrase, "utf-8")
    hashed: bytes = kdf.derive(passphrase_bytes)
    
    # Return everything needed to verify later
    return {
        "salt": salt.hex(),
        "hash": hashed.hex()
    }

def check_password(password: str, stored_data: Dict[str, str]) -> bool:
    """Verify a password against its stored hash.
    
    Args:
        password: The password to verify
        stored_data: Dict containing the stored salt and hash
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        # Get the stored salt from hex
        stored_salt: bytes = bytes.fromhex(stored_data["salt"])
        
        # Create KDF instance with same parameters
        password_kdf = Scrypt(
            salt=stored_salt + PEPPER,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        
        # Verify the password
        password_bytes: bytes = bytes(password, "utf-8")
        password_kdf.verify(password_bytes, bytes.fromhex(stored_data["hash"]))
        return True
        
    except Exception:
        return False

if __name__ == "__main__":
    # Test the implementation
    passphrase = input("Please enter your passphrase: ")
    
    # Hash the password
    result = hash_my_password(passphrase)
    
    # Show the results
    print("Algorithm: Scrypt")
    print("Salt: " + result["salt"])
    print("Length: 32")
    print("n: 2**14")
    print("r: 8")
    print("p: 1")
    print("Hashed passphrase: " + result["hash"])