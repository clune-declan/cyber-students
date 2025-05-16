from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler
from .aes_encrypt_decrypt import aes_encrypt
from .hash_passphrases import kdf, salt, pepper

class RegistrationHandler(BaseHandler):

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
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Encrypt personal information
        encrypted_email = aes_encrypt(email)
        encrypted_display = aes_encrypt(display_name)
        encrypted_disability = aes_encrypt(disability) if disability else ''

        # Hash password
        password_bytes = bytes(password, 'utf-8')
        hashed_password = kdf.derive(password_bytes)

        yield self.db.users.insert_one({
            'email': encrypted_email,
            'password_hash': hashed_password.hex(),
            'displayName': encrypted_display,
            'disability': encrypted_disability,
            'password_salt': salt.hex()
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()