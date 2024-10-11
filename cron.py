import textwrap
from datetime import datetime
from statusserv.models import db, Server, IncidentHistory
from statusserv.serv import addIntervalToTotalDownTime
from statusserv.status import checkStatus
from wsgi import app

if __name__ == "__main__":
    lastS = datetime.now()
    print(lastS)
    with app.app_context():
        servers = db.session.execute(db.select(Server)).scalars()
        for server in servers:
            if not server.type == "request":
                continue
            print(server.name)
            statusResponse = checkStatus(host=server.host, port=server.port, protocol=server.protocol)
            if len(statusResponse) > 99:
                statusResponse = textwrap.shorten(statusResponse, width=99, placeholder="...")
            if statusResponse == "Online":
                server.last_seen = datetime.now()
            else:
                if server.last_response == "Online":
                    #TODO: send notification to member
                    incident: IncidentHistory = IncidentHistory(server_id=server.id, time=datetime.now(), response=statusResponse)
                    db.session.add(incident)
                    db.session.commit()
                server.total_downtime = addIntervalToTotalDownTime(server.total_downtime, 5)
            server.last_response = statusResponse
            db.session.commit()
    difference = datetime.now() - lastS
    print(f"Task need {difference.seconds} seconds")