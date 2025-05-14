from tornado.web import authenticated
from .auth import AuthHandler

import json
from api.handlers.aes_encrypt_decrypt import aes_decrypt

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)

        user = self.current_user
        encrypted_data = user.get('personal_data', {})

        self.response['email'] = user['email']
        
        self.response['displayName'] = aes_decrypt(encrypted_data.get('displayName', ''))
        
        self.response['full_name'] = aes_decrypt(encrypted_data.get('full_name', ''))
        
        self.response['address'] = aes_decrypt(encrypted_data.get('address', ''))
        
        self.response['dob'] = aes_decrypt(encrypted_data.get('dob', ''))
        
        self.response['phone_number'] = aes_decrypt(encrypted_data.get('phone_number', ''))
        
        self.response['disabilities'] = json.loads(aes_decrypt(encrypted_data.get('disabilities', '[]')))

        self.write_json()