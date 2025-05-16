"""Handler for user profile endpoint."""
from tornado.web import authenticated
from tornado.gen import coroutine

from .auth import AuthHandler
from .aes_encrypt_decrypt import aes_decrypt

class UserHandler(AuthHandler):
    """Handler for retrieving user profile information."""

    @authenticated
    @coroutine
    def get(self):
        """Handle GET request for user profile.
        
        Requires valid authentication token.
        Returns decrypted user information.
        """
        try:
            self.set_status(200)
            
         
            user = self.current_user
            
          
            self.response['email'] = user['email']
            self.response['displayName'] = aes_decrypt(user['displayName'])
            
            
            if user.get('disability'):
                self.response['disability'] = aes_decrypt(user['disability'])
            
            self.write_json()
            
        except Exception:
            self.send_error(500, message='Internal server error')