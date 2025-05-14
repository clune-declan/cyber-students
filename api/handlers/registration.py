from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler
from .hash_passphrases import PasswordHasher
from .aes_encrypt_decrypt import AESCipher
import os

class RegistrationHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.password_hasher = PasswordHasher()
        self.cipher = AESCipher()

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            disability = body.get('disability', '')
            if disability and not isinstance(disability, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='Invalid input data format!')
            return

        if not email or not password or not display_name:
            self.send_error(400, message='Required fields must be valid!')
            return

        # Hash email for lookup
        email_hash_data = self.password_hasher.hash_passphrase(email)

        user = yield self.db.users.find_one({
            'email_hash': email_hash_data['hash']
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Hash password
        password_hash_data = self.password_hasher.hash_passphrase(password)

        # Encrypt personal data
        encrypted_email = self.cipher.encrypt(email)
        encrypted_display_name = self.cipher.encrypt(display_name)
        encrypted_disability = self.cipher.encrypt(disability) if disability else None

        yield self.db.users.insert_one({
            'email': encrypted_email,
            'email_hash': email_hash_data['hash'],
            'email_salt': email_hash_data['salt'],
            'password_hash': password_hash_data['hash'],
            'password_salt': password_hash_data['salt'],
            'password_params': password_hash_data['params'],
            'displayName': encrypted_display_name,
            'disability': encrypted_disability
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        if disability:
            self.response['disability'] = disability

        self.write_json()