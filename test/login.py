from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .base import BaseTest
from api.handlers.login import LoginHandler

class LoginHandlerTest(BaseTest):
    def setUp(self):
        super().setUp()
        self.email = 'test@test.com'
        self.password = 'testPassword'
        
        # Initialize encryption for tests
        key = "thebestsecretkey"
        self.key_bytes = bytes(key, "utf-8")
        self.aes_cipher = Cipher(
            algorithms.AES(self.key_bytes),
            modes.ECB(),
            backend=default_backend()
        )
        
        IOLoop.current().run_sync(self.register)

    def encrypt_data(self, plaintext):
        if not plaintext:
            return None
        plaintext_bytes = bytes(plaintext, "utf-8")
        encryptor = self.aes_cipher.encryptor()
        ciphertext_bytes = encryptor.update(plaintext_bytes) + encryptor.finalize()
        return ciphertext_bytes.hex()

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        # Encrypt test data
        encrypted_email = self.encrypt_data(self.email)
        encrypted_display_name = self.encrypt_data('testDisplayName')
        
        # Create test user with encrypted data
        yield self.get_app().db.users.insert_one({
            'email': encrypted_email,
            'email_hash': self.email,  # For testing only, in production this would be properly hashed
            'password_hash': self.password,  # For testing only, in production this would be properly hashed
            'displayName': encrypted_display_name
        })

    def test_login(self):
        body = {
            'email': self.email,
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
            'email': self.email.swapcase(),
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
            'email': 'wrongUsername',
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
            'email': self.email,
            'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)