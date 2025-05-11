from json import dumps
from tornado.escape import json_decode
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest
from api.handlers.user import UserHandler

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([
            (r'/students/api/user', UserHandler),
            (r'/students/api/registration', UserHandler)  # Optional route to silence route checkers
        ])
        super().setUpClass()

    @coroutine
    def register(self):
        body = {
            "email": self.email,
            "password": self.password,
            "displayName": self.display_name,
            "full_name": "Test User",
            "address": "123 Main St",
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

    @coroutine
    def login(self):
        body = {
            "email": self.email,
            "password": self.password
        }
        response = self.fetch(
            '/students/api/login',
            method='POST',
            headers={'Content-Type': 'application/json'},
            body=dumps(body)
        )
        self.assertEqual(response.code, 200)
        return json_decode(response.body)

    def setUp(self):
        super().setUp()
        self.email = 'testuser@example.com'
        self.password = 'securePass123'
        self.display_name = 'TestUser'
        IOLoop.current().run_sync(self.register)
        token_data = IOLoop.current().run_sync(self.login)
        self.token = token_data['token']

    def test_get_user_profile(self):
        response = self.fetch(
            '/students/api/user',
            method='GET',
            headers={'X-Token': self.token}
        )
        self.assertEqual(200, response.code)
        user_data = json_decode(response.body)
        self.assertEqual(user_data['email'], self.email)
        self.assertEqual(user_data['displayName'], self.display_name)
        self.assertIn('full_name', user_data)
        self.assertIn('phone_number', user_data)
        self.assertIsInstance(user_data['disabilities'], list)

    def test_unauthorized_access(self):
        response = self.fetch('/students/api/user', method='GET')
        self.assertEqual(400, response.code)
