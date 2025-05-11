from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from api.conf import APP_PEPPER, AES_KEY


def hash_password(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt + APP_PEPPER,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def aes_encrypt(plaintext: str) -> str:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padded = plaintext.encode('utf-8').ljust(32, b'\0')
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext.hex()


class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName') or email
            full_name = body['full_name']
            address = body['address']
            dob = body['dob']
            phone_number = body['phone_number']
            disabilities = body['disabilities']

            if not all(isinstance(field, str) for field in [email, password, display_name, full_name, address, dob, phone_number]):
                raise Exception()
            if not isinstance(disabilities, list):
                raise Exception()
        except Exception:
            self.send_error(400, message='Missing or invalid required fields.')
            return

        user = yield self.db.users.find_one({'email': email}, {})
        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

      
        salt = os.urandom(16)
        password_hash = hash_password(password, salt)

      
        encrypted_data = {
            'displayName': aes_encrypt(display_name),
            'full_name': aes_encrypt(full_name),
            'address': aes_encrypt(address),
            'dob': aes_encrypt(dob),
            'phone_number': aes_encrypt(phone_number),
            'disabilities': aes_encrypt(json.dumps(disabilities))
        }

        yield self.db.users.insert_one({
            'email': email,
            'password_hash': password_hash.hex(),
            'salt': salt.hex(),
            'personal_data': encrypted_data
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['message'] = 'Registration successful'
        self.write_json()