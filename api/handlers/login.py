from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
import secrets
from .base import BaseHandler
from .hash_passphrases import PasswordHasher
from .aes_encrypt_decrypt import AESCipher

class LoginHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.password_hasher = PasswordHasher()
        self.cipher = AESCipher()

    @coroutine
    def generate_token(self, email_hash):
        token = secrets.token_hex(32)
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token_data = {
            'token': token,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email_hash': email_hash
        }, {
            '$set': token_data
        })

        return token_data

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
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email or not password:
            self.send_error(400, message='Invalid credentials!')
            return

        # Hash email for lookup
        email_hash_data = self.password_hasher.hash_passphrase(email)
        
        user = yield self.db.users.find_one({
            'email_hash': email_hash_data['hash']
        })

        if user is None:
            self.send_error(403, message='Invalid credentials!')
            return

        # Verify password
        stored_password_data = {
            'hash': user['password_hash'],
            'salt': user['password_salt'],
            'params': user['password_params']
        }
        
        if not self.password_hasher.verify_passphrase(password, stored_password_data):
            self.send_error(403, message='Invalid credentials!')
            return

        # Decrypt user data
        decrypted_email = self.cipher.decrypt(user['email'])
        decrypted_display_name = self.cipher.decrypt(user['displayName'])
        decrypted_disability = self.cipher.decrypt(user['disability']) if user.get('disability') else None

        token = yield self.generate_token(user['email_hash'])

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']
        self.response['email'] = decrypted_email
        self.response['displayName'] = decrypted_display_name
        if decrypted_disability:
            self.response['disability'] = decrypted_disability

        self.write_json()