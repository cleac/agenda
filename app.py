import base64
import datetime
import hashlib
import secrets

from collections import namedtuple

from flask import Flask, request, abort
from flask.ext.sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////work/database/db1.db'
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'asdfasdfasdf'
app.config['PORT'] = 5001

db = SQLAlchemy(app)

# MODEL DECLARATIONS {{{


class Event(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(
        db.String(32), unique=True,
        default=lambda: secrets.token_urlsafe(16),
    )
    title = db.Column(db.Text, nullable=False)
    author_email = db.Column(db.Text, nullable=False)


class EventItem(db.Model):

    (STATUS_ACTIVE,
     STATUS_REMOVED) = range(2)

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    minutes = db.Column(db.Integer, nullable=False)
    event_id = db.Column(db.Integer, nullable=False)
    item_placement = db.Column(db.Integer, nullable=False)
    status = db.Column(
        db.Integer, nullable=False, default=STATUS_ACTIVE)


class AuthorisationHash(db.Model):

    DEFAULT_DAYS_BEFORE_EXPIRE = 60

    @staticmethod
    def make_expiration_date():
        return (
            datetime.datetime.now() +
            datetime.timedelta(AuthorisationHash.DEFAULT_DAYS_BEFORE_EXPIRE)
        )

    hash = db.Column(db.String(255), primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    expiration_date = db.Column(db.DateTime, default=make_expiration_date)

# }}}

# DATA ACCESS LAYER {{{

# Event manipulation {{{

EventContent = namedtuple('EventContent', ['event', 'event_items'])

def get_agenda(agenda_id):
    event = Event.query.get_or_404(agenda_id)
    event_items = (
        EventItem.query
        .filter(
            EventItem.event_id == agenda_id,
            EventItem.status != EventItem.STATUS_REMOVED,
        )
        .order_by(EventItem.item_placement.asc())
        .all()
    )
    return EventContent(event, event_items)


def create_agenda(email, title, items, agenda_id=None):
    agenda, event_items = None, []
    if agenda_id:
        agenda, event_items = get_agenda(agenda_id)
        agenda.title = title
        # TODO: make updation of event_items themselves
        db.session.flush([agenda])
    else:
        agenda = Event(name=name, title=title)
        db.session.add(agenda)
        db.session.flush(agenda)
        event_items = [
            EventItem(
                title=item.title,
                minutes=item.minutes,
                placement=index,
                event_id=agenda.id
            )
            for index, item in enumerate(items)
        ]
        db.session.add_all(event_items)
        db.session.flush(event_items)
    return EventContent(agenda, event_items)
# }}}

# Handle authorisation for editing {{{


def make_authorisation_hash(event_token, email):
    factory = hashlib.sha256()
    factory.update(email)
    factory.update(event_token)
    factory.update(app.config['SECRET_KEY'])
    return factory.digest().decode('ascii')


def create_authorisation(event_token, event_id, email):
    hash = make_authorisation_hash(event_token, email)
    auth_hash = AuthorisationHash.query.get(hash)
    if not auth_hash:
        auth_hash = AuthorisationHash(
            hash=hash,
            event_id=event_id,
        )
        db.session.add(auth_hash)
    auth_hash.expiration_date = AuthorisationHash.make_expiration_date()
    db.session.flush([auth_hash])
    return auth_hash


def get_auth_event(event_token, email):
    hash = make_authorisation_hash(event_token, email)
    auth_hash = AuthorisationHash.query.get(hash)
    if not auth_hash:
        return None
    return auth_hash.event_id

# }}}

# }}}

# WEB CONTROLLERS {{{


@app.route('/')
def login():
    event_hash = request.args.get('hash')
    email_hash = request.args.get('auth')
    if event_hash and email_hash:
        try:
            email = base64.decode(email_hash)
        except TypeError:
            return abort(401)
        event_id = get_auth_event(event_hash, email)
        if event_id:
            return u'Editing event #{}'.format(event_id)
    elif event_hash:
        event = Event.query.get(event_id)
        if not event:
            return abort(404)
        return u'Event #{}'.format(event.id)
    return u'Create'

# }}}
