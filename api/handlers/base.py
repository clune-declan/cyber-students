from json import dumps, loads
from tornado.web import RequestHandler
import traceback

class BaseHandler(RequestHandler):

    @property
    def db(self):
        return self.application.db

    @property
    def executor(self):
        return self.application.executor

    def prepare(self):
        if self.request.body:
            try:
                json_data = loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                self.send_error(400, message='Unable to parse JSON.')
        self.response = dict()

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', '*')
        self.set_header('Access-Control-Allow-Headers', '*')

    def write_error(self, status_code, **kwargs):
        self.response = {
            'status_code': status_code,
            'error': {
                'message': kwargs.get('message', 'Unknown error.'),
                'type': str(kwargs.get('exc_info', [''])[0].__name__) if kwargs.get('exc_info') else None,
                'traceback': traceback.format_exception(*kwargs['exc_info']) if kwargs.get('exc_info') else None
            }
        }
        
        if status_code == 405:
            self.response['error']['message'] = 'Invalid HTTP method.'
            
        self.write_json()

    def write_json(self):
        output = dumps(self.response)
        self.write(output)

    def options(self):
        self.set_status(204)
        self.finish()

