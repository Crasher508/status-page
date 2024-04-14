import string
import secrets
from datetime import datetime
from flask import Blueprint, render_template, redirect, request, url_for, flash
from flask_login import current_user, logout_user
from statusserv.models import db, Server, IncidentHistory, User
from statusserv.utils import check_validate_input, get_hashed_password, check_password

dashboardbp = Blueprint('dashboard', __name__)

def generateAPIKey() -> str:    
    alphabet = string.ascii_letters + string.digits
    return (''.join(secrets.choice(alphabet) for i in range(32))).upper()

@dashboardbp.route('/profile')
def profile():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    flash('Wir versenden aktuell keine automatisierten Nachrichten! Das Feature folgt in kürze.', 'message')
    return render_template('profile.html', user=current_user, servers=db.session.execute(db.select(Server).filter_by(user_id=current_user.id)).scalars())

@dashboardbp.route('/register')
def register_server():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    return render_template('register_server.html')

@dashboardbp.route('/register', methods=['POST'])
def register_server_post():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not request.form["host"] or not request.form["port"] or not request.form["type"] or not request.form["protocol"] or not request.form["visibility"] or not request.form["name"]:
        flash('Es müssen alle Felder ausgefüllt werden!', 'error')
        return redirect(url_for('dashboard.register_server'))
    host = request.form.get("host") 
    port = int(request.form.get("port"))
    type = request.form.get("type")
    protocol = request.form.get("protocol")
    visibility = request.form.get("visibility")
    name = request.form.get("name")
    if not check_validate_input(host) or not check_validate_input(name):
        flash('Es müssen alle Felder korrekt ausgefüllt werden!', 'error')
        return redirect(url_for('dashboard.register_server'))
    if len(name) > 100:
        flash('Der Servername darf nicht länger als 100 Zeichen sein!', 'error')
        return redirect(url_for('dashboard.register_server'))
    availableTypes: list[str] = ["request", "self_answer"]
    if type not in availableTypes:
        flash('Der Typ steht nicht zur Auswahl!', 'error')
        return redirect(url_for('dashboard.register_server'))
    availableProtocols: list[str] = ["https", "http", "mcbe", "mcje", "reachable"]
    if protocol not in availableProtocols:
        flash('Bitte wählen Sie ein verfügbares Protokoll!', 'error')
        return redirect(url_for('dashboard.register_server'))
    if protocol == "https":
        if not host.startswith("https://"):
            flash('Die eingegebene Url muss für das Protokoll HTTPS mit \"https://\" starten!', 'error')
            return redirect(url_for('dashboard.register_server'))
    elif protocol == "http":
        if not host.startswith("http://"):
            flash('Die eingegebene Url muss für das Protokoll HTTP mit \"http://\" starten!', 'error')
            return redirect(url_for('dashboard.register_server'))
    availableVisibilities: list[str] = ["public", "private"]
    if visibility not in availableVisibilities:
        flash('Bitte wählen Sie eine verfügbare Sichtbarkeitsregel!', 'error')
        return redirect(url_for('dashboard.register_server'))
    servers: list[str] = []
    for rawServer in db.session.execute(db.select(Server).filter_by(user_id=current_user.id)).scalars():
        servers.append(rawServer.name)
    if len(servers) >= 2 and "admin" not in current_user.getGroups():
        flash('Sie haben das Maximum von 2 freien Servern erreicht! Bitte kontaktieren Sie einen Administrator.', 'error')
        return redirect(url_for('dashboard.register_server'))
    server = db.session.execute(db.select(Server).filter_by(name=name)).scalar()
    if server:
        flash('Der Servername ist bereits vergeben!', 'error')
        return redirect(url_for('dashboard.register_server'))
    apiKey: str = ""
    while True:
        apiKey = generateAPIKey()
        serverByKey = db.session.execute(db.select(Server).filter_by(api_key=apiKey)).scalar()
        if not serverByKey:
            break
    newServer = Server(user_id=current_user.id, name=name, since=datetime.now(), api_key=apiKey, host=host, port=port, type=type, protocol=protocol, visibility=visibility, total_downtime="0:0:0", last_seen=datetime.now(), last_response="")
    db.session.add(newServer)
    db.session.commit()
    if type == "self_answer":
        flash(f'Sie haben die Rückmeldung per API Key gewählt. Bitte bewaren sie diesen Key sorgfältig auf, wir speichern ihn nur in gehashter Form!Eine Rückmeldung ist alle 4 Minuten möglich.', 'message')
    flash(f'Server erfolgreich hinzugefügt. API Key: {apiKey}', 'message')
    return redirect(url_for('dashboard.profile'))

@dashboardbp.route('/<int:server_id>/edit')
def edit_server(server_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    server = db.session.execute(db.select(Server).filter_by(id=server_id)).scalar()
    if not server:
        flash('Es konnte kein Server mit der angegebenen ID gefunden werden!', 'error')
        return redirect(url_for('dashboard.profile'))
    if server.user_id != current_user.id and "admin" not in current_user.getGroups():
        flash('Fehlende Berechtigungen für diesen Server!', 'error')
        return redirect(url_for('dashboard.profile'))
    return render_template('edit_server.html', server=server, incidents=db.session.execute(db.select(IncidentHistory).filter_by(server_id=server.id)).scalars())

@dashboardbp.route('/<int:server_id>/edit', methods=['POST'])
def edit_server_post(server_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    server = db.session.execute(db.select(Server).filter_by(id=server_id)).scalar()
    if not server:
        flash('Es konnte kein Server mit der angegebenen ID gefunden werden!', 'error')
        return redirect(url_for('dashboard.profile'))
    if server.user_id != current_user.id:
        flash('Fehlende Berechtigungen für diesen Server!', 'error')
        return redirect(url_for('dashboard.profile'))
    name = request.form.get("name", "")
    type = request.form.get("type", "")
    visibility = request.form.get("visibility", "")
    if name == "" or type == "" or visibility == "" or not check_validate_input(name):
        flash('Es müssen alle Felder ausgefüllt werden!', 'error')
        return redirect(url_for('dashboard.edit_server', server_id=server.id))
    if len(name) > 100:
        flash('Der Servername darf nicht länger als 100 Zeichen sein!', 'error')
        return redirect(url_for('dashboard.edit_server', server_id=server.id))
    availableTypes: list[str] = ["request", "self_answer"]
    if type not in availableTypes:
        flash('Der Typ steht nicht zur Auswahl!', 'error')
        return redirect(url_for('dashboard.edit_server', server_id=server.id))
    availableVisibilities: list[str] = ["public", "private"]
    if visibility not in availableVisibilities:
        flash('Bitte wählen Sie eine verfügbare Sichtbarkeitsregel!', 'error')
        return redirect(url_for('dashboard.edit_server', server_id=server.id))
    if server.name != name:
        existingServer = db.session.execute(db.select(Server).filter_by(name=name)).scalar()
        if existingServer:
            flash('Der Servername ist bereits vergeben!', 'error')
            return redirect(url_for('dashboard.edit_server', server_id=server.id))
        server.name = name
    if server.type != type:
        server.type = type
    if server.visibility != visibility:
        server.visibility = visibility
    db.session.commit()
    flash('Änderungen erfolgreich gespeichert.', 'message')
    return redirect(url_for('dashboard.edit_server', server_id=server.id))

@dashboardbp.route('/<int:server_id>/delete', methods=['GET'])
def delete_server(server_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    server = db.session.execute(db.select(Server).filter_by(id=server_id)).scalar()
    if not server:
        flash('Es konnte kein Server mit der angegebenen ID gefunden werden!', 'error')
        return redirect(url_for('dashboard.profile'))
    if server.user_id != current_user.id and "admin" not in current_user.getGroups():
        flash('Fehlende Berechtigungen für diesen Server!', 'error')
        return redirect(url_for('dashboard.profile'))
    for rawServer in db.session.execute(db.select(IncidentHistory).filter_by(server_id=server.id)).scalars():
        db.session.delete(rawServer)
        db.session.commit()
    db.session.delete(server)
    db.session.commit()
    flash('Server erfolgreich gelöscht', 'message')
    return redirect(url_for('dashboard.profile'))

@dashboardbp.route('/change_password')
def change_password():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    return render_template('change_password.html')

@dashboardbp.route('/change_password', methods=['POST'])
def change_password_post():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    oldPassword = request.form.get('old-password', "")
    password = request.form.get('password', "")
    passwordRepeat = request.form.get('password-repeat', "")
    if oldPassword == "" or not check_validate_input(oldPassword) or password == "" or not check_validate_input(password) or passwordRepeat == "" or not check_validate_input(passwordRepeat):
        flash('Bitte überprüfen Sie ihre Eingabe und versuchen Sie es erneut!', 'error')
        return redirect(url_for('dashboard.change_password'))
    if (password != passwordRepeat):
        flash('Ihr neues Password entspricht nicht dem wiederholten Passwort!', 'error')
        return redirect(url_for('dashboard.change_password'))
    if (oldPassword == password):
        flash('Sie können nicht das alte Passwort erneut verwenden!', 'error')
        return redirect(url_for('dashboard.change_password')) 
    if len(password) < 8 or len(password) > 48:
        flash('Ihr Passwort muss eine länge zwischen 8 und 48 Zeichen besitzen! Bitte denken Sie an Sonderzeichen.', 'error')
        return redirect(url_for('dashboard.change_password'))
    user = db.session.execute(db.select(User).filter_by(id=current_user.id)).scalar()
    if not user:
        flash('Ihr Nutzerkonto steht nicht zur Verfügung!', 'error')
        return redirect(url_for('dashboard.change_password'))
    if not check_password(oldPassword, user.password): 
        flash('Das eingegebene alte Passwort ist falsch!', 'error')
        return redirect(url_for('dashboard.change_password'))
    user.password = get_hashed_password(password)
    db.session.commit()
    logout_user()
    flash('Passwort erfolgreich geändert. Melden Sie sich erneut an.', 'message')
    return redirect(url_for('auth.login'))

@dashboardbp.route('/delete')
def delete_account():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    user = db.session.execute(db.select(User).filter_by(id=current_user.id)).scalar()
    if not user:
        flash('Ihr Nutzerkonto steht nicht zur Verfügung!', 'error')
        return redirect(url_for('dashboard.profile'))
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Ihr Nutzerkonto wurde erfolgreich gelöscht.', 'message')
    return redirect(url_for('auth.signup'))