from ownline_backend import app, service_table, history_table
from flask import request, jsonify
from flask_jwt_extended import (jwt_required, get_jwt_identity, get_raw_jwt)
import time as timestamp
from tinydb import Query
from utils import ownline_service_client


@app.route('/api/v1/service', methods=['GET'])
@jwt_required
def get_all_services():
    #current_user_public_id = get_jwt_identity()
    #current_jwt = get_raw_jwt()
    output = []
    output.append(service_table.all())
    return jsonify({"services": output}), 200

@app.route('/api/v1/session/history', methods=['GET'])
@jwt_required
def get_history():
    return jsonify({"hisotry": history_table.all()}), 200

@app.route('/api/v1/session/request', methods=['POST'])
@jwt_required
def request_connection():
    if not request.is_json:
        return jsonify({"msg": "Invalid request"}), 400

    service_public_id = request.json.get('service_id')
    service = service_table.get(Query().public_id == service_public_id)
    if not service_public_id or not service:
        return jsonify({"msg": "Invalid request"}), 400

    duration = request.json.get('duration')
    source_ip = request.remote_addr # or access_route[0] for get HTTP_X_FORWARDED_FOR nginx proxy

    app.logger.info("""
Session request:
    service_name: {}
    service_public_id: {}
    source_ip: {}
    duration: {}""".format(service['name'], service_public_id, source_ip, duration))

    msg = {"action": "add",
           "ip_src": source_ip,
           "service_public_id": service_public_id,
           "api_key": app.config['OWNLINE_API_KEY']}

    if duration is not None:
        msg["duration"] = duration

    response = ownline_service_client.send(msg, timeout=app.config['OWNLINE_RESPONSE_TIMEOUT'])
    if validate_response(response):
        history_table.insert({"session_id": response['session_id'],
                              "service_public_id": service_public_id,
                              "port_dst": response['port_dst'],
                              "duration": response['duration'],
                              "end_timestamp": response['end_timestamp'],
                              "source_ip": source_ip,
                              "type": response['type']})
        return jsonify({"msg": "OK"}), 200
    else:
        return jsonify({"msg": "FAIL"}), 400

@app.route('/api/v1/session/delete', methods=['POST'])
@jwt_required
def delete_session():
    pass

@app.route('/api/v1/public_ip', methods=['GET'])
@jwt_required
def get_public_ip():
    return jsonify({"public_ip": request.remote_addr})  # or access_route[0] for get HTTP_X_FORWARDED_FOR nginx proxy


def validate_response(response):
    if not response:
        return False
    try:
        required_keys = ('port_dst', 'end_timestamp', 'duration', 'type', 'session_id')

        if response['status'] == 'FAIL':
            raise Exception("Request status: FAIL")
        if not all(key in response for key in required_keys):
            raise Exception("Not all required fields included in response: {}".format(response.keys()))
        return True
    except Exception as e:
        app.logger.error(repr(e))
        return False

