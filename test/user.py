from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from api.handlers.user import UserHandler
from .base import BaseTest
import urllib.parse

class UserHandlerTest(BaseTest):
    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    def setUp(self):
        super().setUp()
        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'
        key = "thebestsecretkey"
        self.key_bytes = bytes(key, "utf-8")
        self.aes_cipher = Cipher(
            algorithms.AES(self.key_bytes),
            modes.ECB(),
            backend=default_backend()
        )
        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def encrypt_data(self, plaintext):
        if not plaintext:
            return None
        plaintext_bytes = bytes(plaintext.ljust(16 * ((len(plaintext) + 15) // 16)), "utf-8")
        encryptor = self.aes_cipher.encryptor()
        ciphertext_bytes = encryptor.update(plaintext_bytes) + encryptor.finalize()
        return ciphertext_bytes.hex()

    def decrypt_data(self, encrypted_hex):
        if not encrypted_hex:
            return None
        ciphertext_bytes = bytes.fromhex(encrypted_hex)
        decryptor = self.aes_cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        return str(plaintext_bytes, "utf-8").rstrip()

    @coroutine
    def register(self):
        encrypted_email = self.encrypt_data(self.email)
        encrypted_display_name = self.encrypt_data(self.display_name)
        yield self.get_app().db.users.insert_one({
            'email': encrypted_email,
            'email_hash': self.email,
            'password_hash': self.password,
            'displayName': encrypted_display_name
        })

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email_hash': self.email
        }, {
            '$set': { 
                'token': self.token, 
                'expiresIn': 2147483647 
            }
        })

    def test_user(self):
        response = self.fetch('/user', headers={'X-Token': self.token})
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])

        user = IOLoop.current().run_sync(
            lambda: self.get_app().db.users.find_one({'token': self.token})
        )
        self.assertIsNotNone(user)
        self.assertNotEqual(self.email, user['email'])
        self.assertNotEqual(self.display_name, user['displayName'])
        
        decrypted_email = self.decrypt_data(user['email'])
        decrypted_display_name = self.decrypt_data(user['displayName'])
        self.assertEqual(self.email, decrypted_email)
        self.assertEqual(self.display_name, decrypted_display_name)

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        response = self.fetch('/user', headers={'X-Token': 'wrongToken'})
        self.assertEqual(400, response.code)

    def test_user_expired_token(self):
        IOLoop.current().run_sync(
            lambda: self.get_app().db.users.update_one(
                {'email_hash': self.email},
                {'$set': {'expiresIn': 0}}
            )
        )
        response = self.fetch('/user', headers={'X-Token': self.token})
        self.assertEqual(400, response.code)