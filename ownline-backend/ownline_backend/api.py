from ownline_backend import app, service_table, history_table
from flask import request, jsonify
from flask_jwt_extended import (jwt_required, get_jwt_identity, get_raw_jwt)
import time as timestamp
from tinydb import Query


@app.route('/api/v1/service', methods=['GET'])
@jwt_required
def get_all_services():
    current_user_public_id = get_jwt_identity()
    current_jwt = get_raw_jwt()
    output = []
    output.append(service_table.all())
    return jsonify({"services": output}), 200


@app.route('/api/v1/conn/req', methods=['POST'])
@jwt_required
def request_connection():
    if not request.is_json:
        return jsonify({"msg": "Invalid request"}), 400

    service_public_id = request.json.get('service_id')
    service = service_table.get(Query().public_id == service_public_id)
    if not service_public_id or not service:
        return jsonify({"msg": "Invalid request"}), 400

    time = request.json.get('time')
    source_ip = request.remote_addr # or access_route[0] for get HTTP_X_FORWARDED_FOR nginx proxy

    app.logger.info("Connection request:\n\tservice_name: {}\n\tservice_public_id: {}\n\ttime: {}\n\tsource_ip: {}".format(service_public_id, time, service['name'], source_ip))

    history_table.insert({"type": "req",
                          "service_public_id": service_public_id,
                          "service_name": service['name'],
                          "time": time,
                          "timestamp": timestamp.time(),
                          "source_ip": source_ip})

    return jsonify({"msg": "OK"}), 200


@app.route('/api/v1/public_ip', methods=['GET'])
@jwt_required
def get_public_ip():
    return jsonify({"public_ip": request.remote_addr})  # or access_route[0] for get HTTP_X_FORWARDED_FOR nginx proxy
