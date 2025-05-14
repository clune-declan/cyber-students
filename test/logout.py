from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application
from api.handlers.logout import LogoutHandler
from .base import BaseTest
import urllib.parse

class LogoutHandlerTest(BaseTest):
    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': self.password,
            'displayName': self.display_name
        })

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()
        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'
        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        response = self.fetch('/logout', method='POST', headers={'X-Token': self.token})
        self.assertEqual(200, response.code)

        user = IOLoop.current().run_sync(lambda: self.get_app().db.users.find_one({
            'email': self.email
        }))
        self.assertIsNone(user.get('token'))
        self.assertIsNone(user.get('expiresIn'))

    def test_logout_wrong_token(self):
        response = self.fetch('/logout', method='POST', headers={'X-Token': 'wrongToken'})
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        response = self.fetch('/logout', method='POST', headers={'X-Token': self.token})
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', method='POST', headers={'X-Token': self.token})
        self.assertEqual(400, response_2.code)
