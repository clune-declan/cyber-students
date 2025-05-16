"""Handler for user logout endpoint."""
from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler
from .aes_encrypt_decrypt import aes_encrypt

class LogoutHandler(AuthHandler):
    """Handler for user logout with token invalidation."""

    @authenticated
    @coroutine
    def post(self):
        """Handle POST request for user logout.
        
        Requires valid authentication token.
        Invalidates the current token.
        """
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
