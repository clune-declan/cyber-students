from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from api.handlers.registration import RegistrationHandler
from api.handlers.aes_encrypt_decrypt import aes_decrypt
from .base import BaseTest
import urllib.parse

class RegistrationHandlerTest(BaseTest):
    def setUp(self):
        super().setUp()
        # Initialize encryption for tests
        key = "thebestsecretkey"
        self.key_bytes = bytes(key, "utf-8")
        self.aes_cipher = Cipher(
            algorithms.AES(self.key_bytes),
            modes.ECB(),
            backend=default_backend()
        )

    def decrypt_data(self, encrypted_hex):
        if not encrypted_hex:
            return None
        ciphertext_bytes = bytes.fromhex(encrypted_hex)
        decryptor = self.aes_cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        return str(plaintext_bytes, "utf-8")

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def test_registration(self):
        email = 'test@test.com'
        display_name = 'testDisplayName'
        password = 'testPassword'

        body = {
            'email': email,
            'password': password,
            'displayName': display_name
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])

        # Verify data is encrypted in database
        user = IOLoop.current().run_sync(lambda: self.db.users.find_one({'email': {'$exists': True}}))
        self.assertIsNotNone(user)
        
        # Verify encrypted data
        decrypted_email = aes_decrypt(user['email'])
        decrypted_display_name = aes_decrypt(user['displayName'])
        self.assertEqual(email, decrypted_email)
        self.assertEqual(display_name, decrypted_display_name)
        
        # Verify password is hashed
        self.assertNotEqual(password, user['password_hash'])
        self.assertTrue('password_salt' in user)

    def test_registration_without_display_name(self):
        email = 'test2@test.com'
        password = 'testPassword'

        body = {
            'email': email,
            'password': password
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(email, body_2['displayName'])

        # Verify encryption in database
        user = IOLoop.current().run_sync(lambda: self.db.users.find_one({'email': {'$exists': True}}))
        decrypted_email = aes_decrypt(user['email'])
        self.assertEqual(email, decrypted_email)

    def test_registration_twice(self):
        body = {
            'email': 'test3@test.com',
            'password': 'testPassword',
            'displayName': 'testDisplayName'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(400, response_2.code)  # Changed to match our error code

    def test_registration_with_disability(self):
        email = 'test4@test.com'
        display_name = 'testDisplayName'
        password = 'testPassword'
        disability = 'visual impairment'

        body = {
            'email': email,
            'password': password,
            'displayName': display_name,
            'disability': disability
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])

        # Verify disability is encrypted
        user = IOLoop.current().run_sync(lambda: self.db.users.find_one({'email': {'$exists': True}}))
        decrypted_disability = aes_decrypt(user['disability'])
        self.assertEqual(disability, decrypted_disability)