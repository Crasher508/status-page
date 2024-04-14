import bcrypt
import pyotp
import ipaddress
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, current_user
from statusserv.models import User, MembershipRequest, db
from statusserv.utils import check_validate_input, get_hashed_password, check_password
from datetime import datetime
from io import BytesIO
import qrcode
from base64 import b64encode, b64decode

auth = Blueprint('auth', __name__)

def get_b64encoded_qr_image(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")

def valiteIPAdress(rowAdress: str|None) -> bool:
    if not rowAdress:
        return False
    if rowAdress == "127.0.0.1":
        return False
    try:
        ip = ipaddress.ip_address(rowAdress)
        return True
    except ValueError:
        return False
    except:
        return False
    
def getAuthCodeHash(ip: str, savedCode: str) -> str:
    parts: list[str] = savedCode.split(";")
    if len(parts) != 2:
        return savedCode
    return bcrypt.hashpw((parts[0] + ip).encode(), b64decode(parts[1]))

@auth.route('/login')
def login():
    if "_code" in session: session.pop("_code")
    if "_remU2" in session: session.pop("_remU2")
    if current_user:
        if current_user.is_authenticated:
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    if "_code" in session: session.pop("_code")
    if "_remU2" in session: session.pop("_remU2")
    if current_user:
        if current_user.is_authenticated:
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    email = request.form.get('email', "")
    password = request.form.get('password', "")
    remember = True if request.form.get('remember') else False
    if email == "" or not check_validate_input(email) or password == "" or not check_validate_input(password):
        flash('Bitte überprüfen Sie ihre Logindaten!', 'error')
        return redirect(url_for('auth.login'))
    membershipRequest = db.session.execute(db.select(MembershipRequest).filter_by(email=email)).scalar()
    if membershipRequest:
        flash('Bitte gedulden Sie sich ein wenig! Wir bearbeiten ihre Mitgliedsanfrage aktuell.', 'info')
        return redirect(url_for('auth.login'))

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar()
    if not user or not check_password(password, user.password): 
        flash('Bitte überprüfen Sie ihre Logindaten!', 'error')
        return redirect(url_for('auth.login'))

    newAuthCode = pyotp.random_base32()
    ip = request.remote_addr
    if not valiteIPAdress(ip):
        flash('Transaktion abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    salt = bcrypt.gensalt()
    encoded = b64encode(salt).decode()
    authCode = bcrypt.hashpw((newAuthCode + ip).encode(), salt)
    next = "2fa"
    if user.secret == "":
        next = "2fasetup"
    session["_code"] = f"{newAuthCode};{encoded}"
    session["_remU2"] = remember
    user.transaction = authCode
    db.session.commit()
    return redirect(url_for(f"auth.b{next}"))

@auth.route('/auth2setup')
def b2fasetup():
    if "_code" not in session or "_remU2" not in session:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    ip = request.remote_addr
    if not valiteIPAdress(ip):
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen! Ihre Verbindung ist möglicherweise unsicher.', 'error')
        return redirect(url_for('auth.login'))
    if current_user:
        if current_user.is_authenticated:
            if "_code" in session: session.pop("_code")
            if "_remU2" in session: session.pop("_remU2")
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    code: str = session["_code"]
    authcode: str = getAuthCodeHash(ip, code)
    user = db.session.execute(db.select(User).filter_by(transaction=authcode)).scalar()
    if not user:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    if user.secret != "":
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        return redirect(url_for('auth.b2fa'))
    secret: str = user.setOTPSecret()
    db.session.commit()
    uri = user.getOTPSetupUri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template('auth2setup.html', secret=secret, qr_image=base64_qr_image)

@auth.route('/auth2')
def b2fa():
    if "_code" not in session or "_remU2" not in session:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    ip = request.remote_addr
    if not valiteIPAdress(ip):
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen! Ihre Verbindung ist möglicherweise unsicher.', 'error')
        return redirect(url_for('auth.login'))
    if current_user:
        if current_user.is_authenticated:
            if "_code" in session: session.pop("_code")
            if "_remU2" in session: session.pop("_remU2")
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    code: str = session["_code"]
    authcode: str = getAuthCodeHash(ip, code)
    user = db.session.execute(db.select(User).filter_by(transaction=authcode)).scalar()
    if not user:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    if user.secret == "":
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Login fehlgeschlagen! Keine Zwei Faktor Authorisierung aktiviert!', 'error')
        return redirect(url_for('auth.login'))
    return render_template('auth2.html')

@auth.route('/auth2', methods=['POST'])
def b2fa_post():
    if "_code" not in session or "_remU2" not in session:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    ip = request.remote_addr
    if not valiteIPAdress(ip):
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen! Ihre Verbindung ist möglicherweise unsicher.', 'error')
        return redirect(url_for('auth.login'))
    if current_user:
        if current_user.is_authenticated:
            if "_code" in session: session.pop("_code")
            if "_remU2" in session: session.pop("_remU2")
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    code: str = session["_code"]
    authcode: str = getAuthCodeHash(ip, code)
    user = db.session.execute(db.select(User).filter_by(transaction=authcode)).scalar()
    if not user:
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Vorgang abgebrochen!', 'error')
        return redirect(url_for('auth.login'))
    if user.secret == "":
        if "_code" in session: session.pop("_code")
        if "_remU2" in session: session.pop("_remU2")
        flash('Login fehlgeschlagen! Keine Zwei Faktor Authorisierung aktiviert!', 'error')
        return redirect(url_for('auth.login'))
    code = request.form.get('code', "")
    if code == "" or not check_validate_input(code):
        flash('Bitte füllen Sie alle Felder aus!', 'error')
        return redirect(url_for('auth.login'))
    if len(code) != 6:
        flash('Bitte geben Sie einen gültigen 2FA TOTP Code an!', 'error')
        return redirect(url_for('auth.b2fa'))
    if not user.validateOTP(code):
        flash('Bitte geben Sie einen gültigen 2FA TOTP Code an!', 'error')
        return redirect(url_for('auth.b2fa'))
    remember: bool = session["_remU2"]
    login_user(user, remember=remember)
    user.transaction = ""
    db.session.commit()
    if "_code" in session: session.pop("_code")
    if "_remU2" in session: session.pop("_remU2")
    return redirect(url_for('dashboard.profile'))

@auth.route('/signup')
def signup():
    if "_code" in session: session.pop("_code")
    if "_remU2" in session: session.pop("_remU2")
    if current_user:
        if current_user.is_authenticated:
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    if "_code" in session: session.pop("_code")
    if "_remU2" in session: session.pop("_remU2")
    if current_user:
        if current_user.is_authenticated:
            flash('Sie sind bereits angemeldet!', 'error')
            return redirect(url_for('dashboard.profile'))
    email = request.form.get('email', "")
    name = request.form.get('name', "")
    password = request.form.get('password', "")
    passwordRepeat = request.form.get('password-repeat', "")
    if email == "" or not check_validate_input(email) or name == "" or not check_validate_input(name) or password == "" or not check_validate_input(password) or passwordRepeat == "" or not check_validate_input(passwordRepeat):
        flash('Bitte füllen Sie alle Felder aus!', 'error')
        return redirect(url_for('auth.signup'))
    if len(email) > 50 or "@" not in email or "." not in email:
        flash('Bitte geben Sie eine gültige E-Mail Adresse an!', 'error')
        return redirect(url_for('auth.signup'))
    if len(name) > 50:
        flash('Ihr Benutzername darf höchstens 50 Zeichen lang sein!', 'error')
        return redirect(url_for('auth.signup'))
    if len(password) < 8 or len(password) > 48:
        flash('Ihr Passwort muss eine länge zwischen 8 und 48 Zeichen besitzen! Bitte denken Sie an Sonderzeichen.', 'error')
        return redirect(url_for('auth.signup'))
    if (password != passwordRepeat):
        flash('Ihr Password entspricht nicht dem wiederholten Passwort!', 'error')
        return redirect(url_for('auth.signup'))
    membershipRequest = db.session.execute(db.select(MembershipRequest).filter_by(email=email)).scalar()
    if membershipRequest:
        flash('E-Mail Adresse bereits registriert!')
        return redirect(url_for('auth.signup'))
    membershipRequest = db.session.execute(db.select(MembershipRequest).filter_by(name=name)).scalar()
    if membershipRequest:
        flash('Benutzername bereits registriert!', 'error')
        return redirect(url_for('auth.signup'))
    user = db.session.execute(db.select(User).filter_by(email=email)).scalar()
    if user:
        flash('E-Mail Adresse bereits registriert!', 'error')
        return redirect(url_for('auth.signup'))
    user = db.session.execute(db.select(User).filter_by(name=name)).scalar()
    if user:
        flash('Benutzername bereits registriert!', 'error')
        return redirect(url_for('auth.signup'))
    newMembershipRequest = MembershipRequest(email=email, name=name, password=get_hashed_password(password), since=datetime.now())
    db.session.add(newMembershipRequest)
    db.session.commit()
    flash('Ihr Account wurde erfolgreich erstellt. Die Freigabe kann bis zu 48 Stunden in Anspruch nehmen! Wir melden uns bei Rückfragen. Angegebene Daten können auf Anfrage gelöscht werden.', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
def logout():
    if not current_user:
        flash('Sie sind nicht angemeldet!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Sie sind nicht angemeldet!', 'error')
        return redirect(url_for('auth.login'))
    logout_user()
    return redirect(url_for('home.index'))