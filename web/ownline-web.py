from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash, safe_str_cmp
from config import config
import os
from functools import wraps
import jwt
import datetime
from tinydb import TinyDB, Query
import uuid
import telegram



config_name = os.environ.get('CONFIG_NAME') or 'development'


app = Flask(__name__)
app.config.from_object(config[config_name])
config[config_name].init_app(app)

db = TinyDB(app.config['DATABASE_URI'])
user_table = db.table('user')
service_table = db.table('service')
history_table = db.table('history')

if not app.debug:
    bot = telegram.Bot(token=app.config['TELEGRAM_BOT_TOKEN'])


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            User = Query()
            current_user = user_table.search(User.public_id == data['public_id'])[0] #todo: safe_str_cmp
        except jwt.ExpiredSignatureError:
            app.logger.warn('Token expired!')
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            app.logger.error(e)
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/api/v1/login', methods=['POST'])
def login():
    # Get HTTP Basic Authentication
    auth = request.authorization
    if not app.debug:
        bot.send_message(chat_id=app.config['TELEGRAM_CHAT_ID'], parse_mode='Markdown', text='*Login attempt* `user: {}`'.format(auth.username))

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    User = Query()
    user = user_table.search(User.username == auth.username)[0] #todo: safe_str_cmp
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user['password'], auth.password): # todo: safe_str_cmp
        token = jwt.encode({'public_id': user['public_id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/api/v1/service', methods=['GET'])
@token_required
def get_all_services(current_user):

    output = []

    output.append(service_table.all())

    return jsonify({'services': output})


### REMOVE FRO PROD
if __name__ == '__main__':
    app.run(debug=True)