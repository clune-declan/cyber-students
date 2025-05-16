from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from datetime import datetime

from .base import BaseHandler
from .aes_encrypt_decrypt import aes_encrypt
from .hash_passphrases import hash_my_password

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
       
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName', email)
            full_name = body.get('fullName', '')
            date_of_birth = body.get('dateOfBirth', '')
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

            if full_name and not isinstance(full_name, str):
                self.send_error(400, message='The full name must be a string!')
                return

            if date_of_birth:
                try:
                   
                    datetime.strptime(date_of_birth, '%Y-%m-%d')
                except ValueError:
                    self.send_error(400, message='Date of birth must be in YYYY-MM-DD format!')
                    return

            if disability and not isinstance(disability, str):
                self.send_error(400, message='The disability field must be a string!')
                return

        
            user = yield self.db.users.find_one({
                'email': aes_encrypt(email)
            })

            if user is not None:
                self.send_error(400, message='A user with the given email address already exists!')
                return

          
            password_data = hash_my_password(password)
            encrypted_email = aes_encrypt(email)
            encrypted_display_name = aes_encrypt(display_name)
            encrypted_full_name = aes_encrypt(full_name) if full_name else ''
            encrypted_dob = aes_encrypt(date_of_birth) if date_of_birth else ''
            encrypted_disability = aes_encrypt(disability) if disability else ''

            yield self.db.users.insert_one({
                'email': encrypted_email,
                'password_hash': password_data['hash'],
                'password_salt': password_data['salt'],
                'displayName': encrypted_display_name,
                'fullName': encrypted_full_name,
                'dateOfBirth': encrypted_dob,
                'disability': encrypted_disability
            })

            self.set_status(200)
            self.response['email'] = email
            self.response['displayName'] = display_name
            if full_name:
                self.response['fullName'] = full_name
            if date_of_birth:
                self.response['dateOfBirth'] = date_of_birth
            self.write_json()

        except Exception:
            self.send_error(500, message='Internal server error')