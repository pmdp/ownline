from app import app
from ..core.app_setup import bot, jwt, user_table
from flask import request, jsonify
from werkzeug.security import check_password_hash, safe_str_cmp
from flask_jwt_extended import create_access_token, jwt_refresh_token_required, get_jwt_identity
from tinydb import Query


@app.route('/api/v1/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Invalid request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not app.debug:
        bot.send_message(chat_id=app.config['TELEGRAM_CHAT_ID'], parse_mode='Markdown', text='*Login attempt* `user: {}`'.format(username))

    if not username or not password:
        return jsonify({"msg": "Invalid request"}), 400

    user = user_table.get(Query().username == username)
    if not user:
        return jsonify({"msg": "Invalid request"}), 400

    if check_password_hash(user['password'], password):
        access_token = create_access_token(identity=user['public_id'])
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid request"}), 400


@app.route('/api/v1/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200

@jwt.unauthorized_loader
def unauthorized_loader_callback():
    return jsonify({"msg": "Unauthorized"}), 401


@jwt.expired_token_loader
def expired_token_loader_callback():
    return jsonify({"msg": "Unauthorized"}), 401


@jwt.invalid_token_loader
def invalid_token_loader_callback():
    return jsonify({"msg": "Unauthorized"}), 401
