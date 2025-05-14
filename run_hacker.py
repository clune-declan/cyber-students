import click
from json import loads
from motor.motor_tornado import MotorClient
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from api.conf import MONGODB_HOST, MONGODB_DBNAME

class DataDecryptor:
    def __init__(self):
        # Note: This is for demonstration only. In a real attack, 
        # the attacker would need to obtain the key
        key = "thebestsecretkey"
        self.key_bytes = bytes(key, "utf-8")
        self.aes_cipher = Cipher(
            algorithms.AES(self.key_bytes),
            modes.ECB(),
            backend=default_backend()
        )

    def decrypt(self, encrypted_hex):
        if not encrypted_hex:
            return None
        try:
            # Convert hex to bytes
            ciphertext_bytes = bytes.fromhex(encrypted_hex)
            # Create decryptor
            decryptor = self.aes_cipher.decryptor()
            # Decrypt data
            plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            # Convert back to string
            return str(plaintext_bytes, "utf-8")
        except:
            return "[encrypted]"

@coroutine
def get_users(db):
    decryptor = DataDecryptor()
    cur = db.users.find({}, {
        'email': 1,
        'email_hash': 1,
        'password_hash': 1,
        'displayName': 1,
        'disability': 1
    })
    docs = yield cur.to_list(length=None)
    print('There are ' + str(len(docs)) + ' registered users:')
    
    for doc in docs:
        # Try to decrypt the encrypted fields
        try:
            if 'email' in doc:
                doc['email'] = decryptor.decrypt(doc['email'])
            if 'displayName' in doc:
                doc['displayName'] = decryptor.decrypt(doc['displayName'])
            if 'disability' in doc and doc['disability']:
                doc['disability'] = decryptor.decrypt(doc['disability'])
            
            # Remove the hash fields from display
            doc.pop('email_hash', None)
            doc.pop('password_hash', None)
            
            click.echo(doc)
        except Exception as e:
            click.echo(f"Error processing user: {e}")

@click.group()
def cli():
    pass

@click.command()
def list():
    """List all registered users with decrypted data where possible"""
    db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
    IOLoop.current().run_sync(lambda: get_users(db))

cli.add_command(list)

if __name__ == '__main__':
    cli()