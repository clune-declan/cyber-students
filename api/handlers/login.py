from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify

from api.conf import APP_PEPPER


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    kdf = Scrypt(
        salt=salt + APP_PEPPER,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), expected_hash)
        return True
    except Exception:
        return False


class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
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
            if not all(isinstance(field, str) for field in [email, password]):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
            'email': email
        }, {
            'password_hash': 1,
            'salt': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        try:
            salt = unhexlify(user['salt'])
            stored_hash = unhexlify(user['password_hash'])
        except Exception:
            self.send_error(500, message='Corrupted password data')
            return

        if not verify_password(password, salt, stored_hash):
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']
        self.write_json()