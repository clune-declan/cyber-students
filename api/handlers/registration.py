from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = "thebestsecretkey"
key_bytes = bytes(key, "utf-8")
print("Key: " + key)

aes_cipher = Cipher(algorithms.AES(key_bytes),
                    modes.ECB(),
                    backend=default_backend())

aes_encryptor = aes_cipher.encryptor()
aes_decryptor = aes_cipher.decryptor()

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            disability = body.get('disability')  # added disability requirement
            if disability is not None and not isinstance(disability, str):
                raise Exception()
                
                
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
            
        # encrypt email
        print("Plaintext: " + email)
        email_bytes = bytes(email, "utf-8")
        email_ciphertext_bytes = aes_encryptor.update(email_bytes) + aes_encryptor.finalize()
        email_ciphertext = email_ciphertext_bytes.hex()
        print("Ciphertext: " + email_ciphertext)
         
        # encrypt dispalay name
        print("Plaintext: " + display_name)
        display_name_bytes = bytes(display_name, "utf-8")
        display_name_ciphertext_bytes = aes_encryptor.update(display_name_bytes) + aes_encryptor.finalize()
        display_name_ciphertext = display_name_ciphertext_bytes.hex()
        print("Ciphertext: " + display_name_ciphertext)

        yield self.db.users.insert_one({
            'email': email_ciphertext,
            'password': password,
            'displayName': display_name_ciphertext
            'disability': disability  
        })
        
        # decrypt email
        email_plaintext_bytes = aes_decryptor.update(email_ciphertext_bytes) + aes_decryptor.finalize()
        email_plaintext = str(email_plaintext_bytes, "utf-8")
        print("Original Plaintext: " + email_plaintext)
        
        # decrypt display name
        display_name_plaintext_bytes = aes_decryptor.update(display_name_ciphertext_bytes) + aes_decryptor.finalize()
        display_name_plaintext = str(display_name_plaintext_bytes, "utf-8")
        print("Original Plaintext: " + display_name_plaintext)

        self.set_status(200)
        self.response['email'] = email_plaintext
        self.response['displayName'] = display_name_plaintext
        self.response['disability'] = disability

        self.write_json()
