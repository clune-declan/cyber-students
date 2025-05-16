from datetime import datetime, timedelta
from time import mktime
from uuid import uuid4
from tornado.escape import json_decode
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler
from .aes_encrypt_decrypt import aes_encrypt
from .hash_passphrases import check_password

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in
        }

        yield self.db.users.update_one({
            'email': aes_encrypt(email)
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']

            if not email or not isinstance(email, str):
                self.send_error(400, message='The email address is invalid!')
                return

            if not password or not isinstance(password, str):
                self.send_error(400, message='The password is invalid!')
                return

        
            user = yield self.db.users.find_one({
                'email': aes_encrypt(email)
            }, {
                'password_hash': 1,
                'password_salt': 1
            })

            if user is None:
                self.send_error(403, message='The email address and password are invalid!')
                return

       
            if not check_password(password, {
                'hash': user['password_hash'],
                'salt': user['password_salt']
            }):
                self.send_error(403, message='The email address and password are invalid!')
                return

            token = yield self.generate_token(email)

            self.set_status(200)
            self.response['token'] = token['token']
            self.response['expiresIn'] = token['expiresIn']
            self.write_json()

        except Exception:
            self.send_error(400, message='You must provide an email address and password!')
