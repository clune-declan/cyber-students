import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


PEPPER = os.urandom(16)

def hash_my_password(passphrase):

    salt = os.urandom(16)
    
 
    kdf = Scrypt(salt=salt + PEPPER, length=32, n=2**14, r=8, p=1)
    
 
    passphrase_bytes = bytes(passphrase, "utf-8")
    hashed = kdf.derive(passphrase_bytes)
    
   
    return {
        "salt": salt.hex(),
        "hash": hashed.hex()
    }

def check_password(password, stored_data):
 
    try:
        
        stored_salt = bytes.fromhex(stored_data["salt"])
        
        
        password_kdf = Scrypt(salt=stored_salt + PEPPER, length=32, n=2**14, r=8, p=1)
        
   
        password_bytes = bytes(password, "utf-8")
        password_kdf.verify(password_bytes, bytes.fromhex(stored_data["hash"]))
        return True
        
    except Exception:
        return False

if __name__ == "__main__":
    
    passphrase = input("Please enter your passphrase: ")
    
   
    result = hash_my_password(passphrase)
    
    
    print("Algorithm: Scrypt")
    print("Salt: " + result["salt"])
    print("Length: 32")
    print("n: 2**14")
    print("r: 8")
    print("p: 1")
    print("Hashed passphrase: " + result["hash"])