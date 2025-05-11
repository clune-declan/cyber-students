from json import dumps
from tornado.escape import json_decode
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest
from api.handlers.login import LoginHandler

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([
            (r'/login', LoginHandler),
            (r'/students/api/registration', LoginHandler)  # Optional, if routing needed for test
        ])
        super().setUpClass()

    @coroutine
    def register(self):
        body = {
            "email": self.email,
            "password": self.password,
            "displayName": "TestUser",
            "full_name": "Test User",
            "address": "123 Main Street",
            "dob": "2000-01-01",
            "phone_number": "1234567890",
            "disabilities": ["none"]
        }
        response = self.fetch(
            '/students/api/registration',
            method='POST',
            headers={'Content-Type': 'application/json'},
            body=dumps(body)
        )
        self.assertEqual(response.code, 200)

    def setUp(self):
        super().setUp()
        self.email = 'test@test.com'
        self.password = 'testPassword'
        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
            'email': self.email,
            'password': self.password
        }
        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)
        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
            'email': self.email.swapcase(),
            'password': self.password
        }
        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)
        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
            'email': 'wrongUsername',
            'password': self.password
        }
        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
            'email': self.email,
            'password': 'wrongPassword'
        }
        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)