from flask import Flask
from config import config
from flask_jwt_extended import JWTManager
import os
from tinydb import TinyDB
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
import telegram

# Loads configuration by environment
config_name = os.environ.get('CONFIG_NAME') or 'development'

# Initialize flask app
app = Flask(__name__)
app.config.from_object(config[config_name])
config[config_name].init_app(app)

# Initialize flask-jwt-extended extension
jwt = JWTManager(app)

# Initialize tiny database
db = TinyDB(app.config['DATABASE_URI'])
user_table = db.table('user')
service_table = db.table('service')
history_table = db.table('history')

# Initialize telegram bot notification service
if not app.debug:
    bot = telegram.Bot(token=app.config['TELEGRAM_BOT_TOKEN'])
else:
    bot = None

import ownline_backend.auth
import ownline_backend.api
