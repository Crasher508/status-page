from flask import Blueprint, render_template
from models import Server, db

homebp = Blueprint('home', __name__)

@homebp.route('/')
def index():
    return render_template('index.html', servers=db.session.execute(db.select(Server).filter_by(visibility="public")).scalars())