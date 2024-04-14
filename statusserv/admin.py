from flask import Blueprint, render_template, redirect, request, url_for, flash
from flask_login import current_user
from statusserv.models import db, User, Server, MembershipRequest

adminbp = Blueprint('admin', __name__)

@adminbp.route('/membership_requests')
def membership_requests():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    return render_template('membership_requests.html', membership_requests = db.session.execute(db.select(MembershipRequest)).scalars())

@adminbp.route('/membership_requests/accept/<int:request_id>', methods=['GET'])
def accept_membership_request(request_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    membership_request = db.session.execute(db.select(MembershipRequest).filter_by(id=request_id)).scalar()
    if not membership_request:
        flash('Es existiert keine Mitgliedschaftsanfrage mit der angegebenen RequestId!', 'error')
        return redirect(url_for('admin.membership_requests'))
    new_user = User(email=membership_request.email, password=membership_request.password, name=membership_request.name)
    db.session.add(new_user)
    db.session.commit()
    db.session.delete(membership_request)
    db.session.commit()
    flash('Die Mitgliedschaftsanfrage wurde erfolgreich akzeptiert.', 'message')
    return redirect(url_for('admin.membership_requests'))

@adminbp.route('/membership_requests/delete/<int:request_id>', methods=['GET'])
def delete_membership_request(request_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    membership_request = db.session.execute(db.select(MembershipRequest).filter_by(id=request_id)).scalar()
    if not membership_request:
        flash('Es existiert keine Mitgliedschaftsanfrage mit der angegebenen Id!', 'error')
        return redirect(url_for('admin.membership_requests'))
    db.session.delete(membership_request)
    db.session.commit()
    flash('Die Mitgliedschaftsanfrage wurde erfolgreich gelöscht.', 'message')
    return redirect(url_for('admin.membership_requests'))

@adminbp.route('/servers')
def list_servers():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    return render_template('servers.html', servers = db.session.execute(db.select(Server)).scalars())

@adminbp.route('/users')
def users():
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    return render_template('users.html', users = db.session.execute(db.select(User)).scalars())

@adminbp.route('/users/delete/<int:user_id>', methods=['GET'])
def delete_user(user_id: int):
    if not current_user:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if not current_user.is_authenticated:
        flash('Anmeldung erforderlich!', 'error')
        return redirect(url_for('auth.login'))
    if "admin" not in current_user.getGroups():
        flash('Account mit höheren Berechtigungen erforderlich!', 'error')
        return redirect(url_for('dashboard.profile'))
    user = db.session.execute(db.select(User).filter_by(id=user_id)).scalar()
    if not user:
        flash('Es existiert keine Benutzer mit der angegebenen Id!', 'error')
        return redirect(url_for('admin.users'))
    db.session.delete(user)
    db.session.commit()
    flash('Der Benutzer wurde erfolgreich gelöscht.', 'message')
    return redirect(url_for('admin.users'))