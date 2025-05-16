from tornado.web import authenticated
from tornado.gen import coroutine

from .auth import AuthHandler
from .aes_encrypt_decrypt import aes_decrypt

class UserHandler(AuthHandler):

    @authenticated
    @coroutine
    def get(self):
        try:
            self.set_status(200)
            
            # Get encrypted user data
            user = self.current_user
            
            # Return decrypted basic info
            self.response['email'] = user['email']
            self.response['displayName'] = aes_decrypt(user['displayName'])
            
            # Add disability info if present
            if user.get('disability'):
                self.response['disability'] = aes_decrypt(user['disability'])
            
            self.write_json()
            
        except Exception:
            self.send_error(500, message='Internal server error')