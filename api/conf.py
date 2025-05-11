PORT = 4001

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

APP_PEPPER = b'fixed_pepper_123!'             
AES_KEY = b'thebestsecretkey123'  

PBKDF2_ITERATIONS = 100_000
SALT = b'\x01\x02\x03...\x10'