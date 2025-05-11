from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler

class LogoutHandler(AuthHandler):

    @authenticated
    @coroutine
    def post(self):
        yield self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$unset': {
                'token': "",
                'expiresIn': ""
            }
        })

        self.current_user = None

        self.set_status(200)
        self.response['message'] = 'Logout successful'
        self.write_json()
