import pyotp
from datetime import datetime
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine, StringEncryptedType
from sqlalchemy.types import String, Integer, DateTime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from base64 import b64encode, b64decode

key: str = ""

def getKey() -> str:
    return key

db = SQLAlchemy()

class MembershipRequest(db.Model):
    id = db.Column(Integer, primary_key=True)
    email = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    password = db.Column(String(100))
    name = db.Column(StringEncryptedType(type_in=String(1000), length=1000, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    since = db.Column(DateTime)

class User(UserMixin, db.Model):
    id = db.Column(Integer, primary_key=True)
    email = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    password = db.Column(String(100))
    name = db.Column(StringEncryptedType(type_in=String(1000), length=1000, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    since = db.Column(DateTime)
    secret = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'))
    notification = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'))
    transaction = db.Column(String(100)) 

    def __init__(self, email: str, password: str, name: str):
        self.email = email
        self.password = password
        self.name = name
        self.since = datetime.now()
        self.secret = ""
        self.notification = ""
        self.transaction = ""

    def getGroups(self) -> list[str]:
        groups: list[str] = []
        for userGroup in db.session.execute(db.select(Usergroup).filter_by(user_id=self.id)).scalars():
            groups.append(userGroup.name)
        return groups

    def setOTPSecret(self) -> str:
        generated = pyotp.random_base32()
        self.secret = b64encode(generated.encode()).decode()
        return generated

    def getOTPSetupUri(self) -> str:
        otp_token: str = b64decode(self.secret)
        return pyotp.totp.TOTP(otp_token).provisioning_uri(
            name=self.name, issuer_name="StatusServer")

    def validateOTP(self, user_otp: str):
        totp = pyotp.parse_uri(self.getOTPSetupUri())
        return totp.verify(user_otp)
    
    def getNotificationString(self) -> str:
        notificationStore: list[str] = self.notification.split(";")
        if notificationStore != 2:
            return ""
        return f"{notificationStore[0].upper}<br>{notificationStore[1]}"
    
    def getServerCount(self) -> int:
        users = db.session.execute(db.select(Server).filter_by(user_id=self.id)).scalars()
        i: int = 0
        for user in users:
            i += 1
        return i

class Server(db.Model):
    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, nullable=False, primary_key=False)
    name = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    since = db.Column(DateTime)
    api_key = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'), unique=True)
    host = db.Column(StringEncryptedType(type_in=String(100), length=100, key=getKey(), engine=AesEngine, padding='pkcs5'))
    port = db.Column(Integer)
    type = db.Column(String(12))
    protocol = db.Column(String(10))
    visibility = db.Column(String(10))
    total_downtime = db.Column(String(20))
    last_seen = db.Column(DateTime)
    last_response = db.Column(String(100))

    def calcOnlinePercentage(self) -> float:
        parts: list[str] = self.total_downtime.split(":")
        if not len(parts) == 3:
            return 100
        minutes: int = int(parts[2]) + int(parts[1]) + (int(parts[0]) * 1440)
        if minutes < 1:
            return 100
        since: datetime = self.since
        online = datetime.now() - since
        onlineAsMinutes: int = (online.total_seconds() // 60)
        percentage: float = ((onlineAsMinutes - minutes) * 100) / onlineAsMinutes
        return 0 if percentage < 0 else round(percentage, 2)
    
    def lastResponseInMuntes(self) -> int:
        return ((datetime.now() - self.last_seen).total_seconds() // 60.0)
    
    def getProtocol(self) -> str:
        switch={
            'https': 'Https Website Anfrage',
            'http': 'Http Website Anfrage',
            'mcbe': 'MC Bedrock Server ping',
            'mcje': 'MC Java Server ping',
            'reachable': 'Port Anfrage'
        }
        return switch.get(self.protocol, "Port Anfrage")
    
    def getType(self) -> str:
        return 'Unser System stellt die Anfrage' if self.type == "request" else 'Rückmeldung per API Key'
    
    def getVisibility(self) -> str:
        return 'Öffentlich' if self.visibility == 'public' else 'Privat'
    
    def getStatus(self) -> str:
        return self.last_response if self.lastResponseInMuntes() < 10 else (self.last_response if self.last_response == 'Offline' else 'Timeout')

class IncidentHistory(db.Model):
    id = db.Column(Integer, primary_key=True)
    server_id = db.Column(Integer, nullable=False, primary_key=False)
    time = db.Column(DateTime)
    response = db.Column(String(100))

class Usergroup(db.Model):
    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, nullable=False, primary_key=False)
    name = db.Column(String(20))