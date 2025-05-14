import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# make a new pepper when app starts
pepper = os.urandom(16)

def hash_my_password(passphrase):
    # make a new salt for each user
    salt = os.urandom(16)
    
    # combine salt and pepper
    combined = salt + pepper
    
    # setup the hasher
    kdf = Scrypt(
        salt=combined,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    
    # convert password to bytes and hash it
    passphrase_bytes = bytes(passphrase, "utf-8")
    hashed = kdf.derive(passphrase_bytes)
    
    # return everything we need to check it later
    return {
        "salt": salt.hex(),
        "hash": hashed.hex()
    }

def check_password(password, stored_stuff):
    # get the salt from hex
    salt = bytes.fromhex(stored_stuff["salt"])
    
    # combine with our pepper
    combined = salt + pepper
    
    # setup the hasher same as before
    kdf = Scrypt(
        salt=combined,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    
    # check if password matches
    try:
        password_bytes = bytes(password, "utf-8")
        kdf.verify(password_bytes, bytes.fromhex(stored_stuff["hash"]))
        return True
    except:
        return False

# test it works
if __name__ == "__main__":
    passphrase = input("Please enter your passphrase: ")
    
    # hash it
    result = hash_my_password(passphrase)
    
    # show what we got
    print("Algorithm: Scrypt")
    print("Salt: " + result["salt"])
    print("Length: 32")
    print("n: 2**14")
    print("r: 8")
    print("p: 1")
    print("Hashed passphrase: " + result["hash"])