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
            # Parse and validate input
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise ValueError('Email must be a string')
            password = body['password']
            if not isinstance(password, str):
                raise ValueError('Password must be a string')
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise ValueError('Display name must be a string')
            disability = body.get('disability', '')
            if disability and not isinstance(disability, str):
                raise ValueError('Disability must be a string')

            if not email:
                raise ValueError('The email address is invalid!')

            if not password:
                raise ValueError('The password is invalid!')

            if not display_name:
                raise ValueError('The display name is invalid!')

            # Check if user exists
            user = yield self.db.users.find_one({
                'email': email
            }, {})

            if user is not None:
                raise ValueError('A user with the given email address already exists!')

            try:
                # Encrypt personal information
                encrypted_email = aes_encrypt(email)
                encrypted_display = aes_encrypt(display_name)
                encrypted_disability = aes_encrypt(disability) if disability else ''

                # Hash password
                password_bytes = bytes(password, 'utf-8')
                hashed_password = kdf.derive(password_bytes)

                # Insert into database
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

            except Exception as e:
                info(f"Error during encryption/database operation: {str(e)}")
                self.send_error(500, message='Internal server error during user creation')
                return

        except ValueError as e:
            self.send_error(400, message=str(e))
            return
        except Exception as e:
            info(f"Unexpected error: {str(e)}")
            self.send_error(500, message='Internal server error')
            return