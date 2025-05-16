"""Handler for user registration endpoint."""
from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler
from .aes_encrypt_decrypt import aes_encrypt
from .hash_passphrases import hash_my_password

class RegistrationHandler(BaseHandler):
    """Handler for registering new users with encrypted data storage."""

    @coroutine
    def post(self):
        """Handle POST request for user registration.
        
        Expects JSON body with:
        - email: string
        - password: string
        - displayName: string (optional)
        - disability: string (optional)
        """
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName', email)
            disability = body.get('disability', '')

            if not email or not isinstance(email, str):
                self.send_error(400, message='The email address is invalid!')
                return

            if not password or not isinstance(password, str):
                self.send_error(400, message='The password is invalid!')
                return

            if not display_name or not isinstance(display_name, str):
                self.send_error(400, message='The display name is invalid!')
                return

            if disability and not isinstance(disability, str):
                self.send_error(400, message='The disability field must be a string!')
                return

            # Check if user exists using encrypted email
            user = yield self.db.users.find_one({
                'email': aes_encrypt(email)
            })

            if user is not None:
                self.send_error(400, message='A user with the given email address already exists!')
                return

            # Hash password and encrypt sensitive data
            password_data = hash_my_password(password)
            encrypted_email = aes_encrypt(email)
            encrypted_display_name = aes_encrypt(display_name)
            encrypted_disability = aes_encrypt(disability) if disability else ''

            # Store encrypted and hashed data
            yield self.db.users.insert_one({
                'email': encrypted_email,
                'password_hash': password_data['hash'],
                'password_salt': password_data['salt'],
                'displayName': encrypted_display_name,
                'disability': encrypted_disability
            })

            self.set_status(200)
            self.response['email'] = email
            self.response['displayName'] = display_name
            self.write_json()

        except Exception:
            self.send_error(500, message='Internal server error')