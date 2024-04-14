import os
import json
import textwrap
from datetime import datetime
from flask import Flask
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler as scheduler
from base64 import urlsafe_b64encode
from statusserv.models import db, key, User, Server, IncidentHistory
from statusserv.status import checkStatus

def create_app(json_object):
    if ("mysql" not in json_object) or ("secret_key" not in json_object) or ("database_key" not in json_object):
        print("Config missing arguments!")
        return None
    mysql_object = json_object["mysql"]
    if ("host" not in mysql_object) or ("port" not in mysql_object) or ("user" not in mysql_object) or ("password" not in mysql_object) or ("database" not in mysql_object):
        print("Mysql credentials config missing arguments!")
        return None
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    DATABASE_URI = "mysql://{0}:{1}@{2}:{3}/{4}"
    app.config['SECRET_KEY'] = str(json_object["secret_key"])
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI.format(str(mysql_object["user"]), str(mysql_object["password"]), str(mysql_object["host"]), int(mysql_object["port"]), str(mysql_object["database"]))
    app.config['DATABASE_ENCRYPTION_KEY'] = json_object["database_key"]
    global key
    key = app.config['DATABASE_ENCRYPTION_KEY']
    db.init_app(app)
    with app.app_context():
        db.create_all()
        db.session.commit()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # return db.session.execute(db.select(User).filter_by(id=user_id)).scalar()
        return db.get_or_404(User, int(user_id))
    from statusserv.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    from statusserv.home import homebp as home_blueprint
    app.register_blueprint(home_blueprint)
    from statusserv.admin import adminbp as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix="/admin")
    from statusserv.api import apibp as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix="/api")
    from statusserv.dashboard import dashboardbp as dashboard_blueprint
    app.register_blueprint(dashboard_blueprint, url_prefix="/dashboard")

    return app

def createConfig(file_name: str):
    if os.path.exists(file_name):
        print("Config already exists")
        return
    defaults = {
        "mysql": {
            "host": "127.0.0.1",
            "port": 3306,
            "user": "",
            "password": "",
            "database": ""
        },
        "host": "127.0.0.1",
        "port": 8080,
        "secret_key": "",
        "database_key": urlsafe_b64encode(os.urandom(32)).decode()
    }
    json_object = json.dumps(defaults)
    with open(file_name, "w") as outfile:
        outfile.write(json_object)
    outfile.close()

def start(run: bool = False) -> Flask|None:
    file_name = "config.json"
    createConfig(file_name)
    if not os.path.exists(file_name):
        print("Config does not exists!")
        return None
    with open(file_name, 'r') as openfile:
        json_object = json.load(openfile)
    openfile.close()
    if ("host" not in json_object) or ("port" not in json_object):
        print("Config is unresolved!")
        return None
    app = create_app(json_object)
    if not app:
        return None
    startScheduler(app)
    if run:
        app.run(host=str(json_object["host"]), port=int(json_object["port"]))
    return app

def addIntervalToTotalDownTime(downtime: str, interval: int = 5) -> str:
    parts: list[str] = downtime.split(":")
    if not len(parts) == 3:
        return "0:0:5"
    days: int = int(parts[0])
    hours: int = int(parts[1])
    minutes: int = int(parts[2])
    minutes = minutes + (hours * 60) + (days * 1440) + interval
    days = hours = 0
    if minutes >= 60:
        hours = (minutes // 60)
        minutes = (minutes % 60)
    if hours >= 24:
        days = (hours // 24)
        hours = (hours % 24)
    return f"{days}:{hours}:{minutes}"

def scheduleTask(app: Flask):
    lastS = datetime.now()
    print(lastS)
    with app.app_context():
        servers = db.session.execute(db.select(Server)).scalars()
        for server in servers:
            if not server.type == "request":
                continue
            statusResponse = checkStatus(host=server.host, port=server.port, protocol=server.protocol)
            if len(statusResponse) > 99:
                statusResponse = textwrap.shorten(statusResponse, width=99, placeholder="...")
            if statusResponse == "Online":
                server.last_seen = datetime.now()
            else:
                if server.last_response == "Online":
                    #send notification to member
                    incident: IncidentHistory = IncidentHistory(server_id=server.id, time=datetime.now(), response=statusResponse)
                    db.session.add(incident)
                    db.session.commit()
                server.total_downtime = addIntervalToTotalDownTime(server.total_downtime, 5)
            server.last_response = statusResponse
            db.session.commit()
    difference = datetime.now() - lastS
    print(f"Task need {difference.seconds} seconds")

def startScheduler(app: Flask):
    sch = scheduler()
    sch.add_job(scheduleTask, trigger='interval', minutes=5, args=[app])
    sch.start()