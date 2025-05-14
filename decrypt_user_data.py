import json
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from api.conf import AES_KEY  # Make sure conf.py is accessible

def aes_decrypt(ciphertext_hex: str) -> str:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(bytes.fromhex(ciphertext_hex)) + decryptor.finalize()
    return padded.rstrip(b'\0').decode('utf-8')


client = MongoClient("localhost", 27017)  
db = client["cyberStudents"]             


user = db.users.find_one({}, {"email": 1, "personal_data": 1, "_id": 0})
if not user:
    print("No users found.")
    exit()


decrypted = {}
for field, value in user.get("personal_data", {}).items():
    try:
        decrypted[field] = aes_decrypt(value)
    except Exception:
        decrypted[field] = "[decryption failed]"

print(f"\n📨 Decrypted personal data for: {user['email']}")
print(json.dumps(decrypted, indent=2))