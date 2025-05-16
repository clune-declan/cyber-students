from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler
from .aes_encrypt_decrypt import aes_encrypt

class LogoutHandler(AuthHandler):

    @authenticated
    @coroutine
    def post(self):
        try:
            yield self.db.users.update_one({
                'email': aes_encrypt(self.current_user['email'])
            }, {
                '$set': {
                    'token': None,
                    'expiresIn': None
                }
            })

            self.current_user = None
            self.set_status(200)
            self.write_json()

        except Exception:
            self.send_error(500, message='Internal server error')