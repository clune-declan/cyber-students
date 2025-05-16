"""Base handler for all API endpoints with common functionality."""
from json import dumps, loads
from tornado.web import RequestHandler

class BaseHandler(RequestHandler):
    """Base handler class implementing common functionality for all endpoints."""

    def initialize(self):
        """Initialize handler with empty response dictionary."""
        self.response = dict()

    @property
    def db(self):
        """Get the database instance."""
        return self.application.db

    @property
    def executor(self):
        """Get the executor instance."""
        return self.application.executor

    def prepare(self):
        """Prepare the request by parsing JSON body if present."""
        if self.request.body:
            try:
                json_data = loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                self.send_error(400, message='Unable to parse JSON.')

    def set_default_headers(self):
        """Set default headers including security headers."""
        self.set_header('Content-Type', 'application/json')
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.set_header('Access-Control-Allow-Headers', 'X-Token, Content-Type')
        self.set_header('X-Content-Type-Options', 'nosniff')
        self.set_header('X-Frame-Options', 'DENY')
        self.set_header('Content-Security-Policy', "default-src 'self'")

    def write_error(self, status_code, **kwargs):
        """Write error response in JSON format."""
        if 'message' not in kwargs:
            if status_code == 405:
                kwargs['message'] = 'Invalid HTTP method.'
            else:
                kwargs['message'] = 'Unknown error.'
        self.response = kwargs
        self.write_json()

    def write_json(self):
        """Write response in JSON format."""
        output = dumps(self.response)
        self.write(output)

    def options(self):
        """Handle OPTIONS requests for CORS."""
        self.set_status(204)
        self.finish()

    def data_received(self, chunk):
        """Handle streaming data - not used in this implementation."""
        pass