import click
from json import loads
from motor.motor_tornado import MotorClient
from tornado.gen import coroutine
from tornado.ioloop import IOLoop

from api.conf import MONGODB_HOST, MONGODB_DBNAME

@coroutine
def get_users(db):
    cur = db.users.find({}, {
        'email': 1,
        'email_hash': 1,
        'password_hash': 1,
        'password_salt': 1,
        'displayName': 1,
        'disability': 1,
        'token': 1,
        'expiresIn': 1
    })
    docs = yield cur.to_list(length=None)
    for doc in docs:
        if '_id' in doc:
            del doc['_id']
        click.echo(doc)

@click.group()
def cli():
    pass

@click.command()
def list():
    db = MotorClient(**MONGODB_HOST)[MONGODB_DBNAME]
    IOLoop.current().run_sync(lambda: get_users(db))

cli.add_command(list)

if __name__ == '__main__':
    cli()