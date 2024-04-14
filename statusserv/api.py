from datetime import datetime
from flask import Blueprint, request, jsonify
from statusserv.models import db, Server, IncidentHistory

apibp = Blueprint('api', __name__)

@apibp.route('/handshake')
def handshake():
    return "Method Not Allowed", 405

@apibp.route('/handshake', methods=['POST'])
def handshake_post():
    server_id: int = request.form.get("server_id", 0)
    apiKey: str = request.form.get("apikey", "")
    message: str = request.form.get("message", "")
    if apiKey == "" or message == "" or server_id == 0:
        return "Wrong request", 400
    server = db.session.execute(db.select(Server).filter_by(id=server_id)).scalar()
    if not server:
        return "Wrong request", 400
    if server.api_key != apiKey:
        return "Wrong request", 400
    if server.lastResponseInMuntes() < 4:
        return "Cooldown of 5 minutes!", 400
    if message == "Offline":
        message = "Server response: Offline"
    server.last_seen = datetime.now()
    server.last_response = message
    db.session.commit()
    return "Ok", 200

@apibp.route('/request_info/<string:apikey>')
def request_info(apikey: str):
    if apikey == "":
        return jsonify(version=0)
    server = db.session.execute(db.select(Server).filter_by(api_key=apikey)).scalar()
    if not server:
        return jsonify(version=0)
    incidents =({
        'time': incident.time,
        'response': incident.response,
    } for incident in db.session.execute(db.select(IncidentHistory).filter_by(server_id=server.id)).scalars())
    response_data = {
        'name': server.name,
        'last_seen': server.last_seen,
        'last_response': server.last_response,
        'incidents': list(incidents)
    }
    return jsonify(version=1, **response_data)