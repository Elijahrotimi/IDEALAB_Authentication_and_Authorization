from flask_sqlalchemy import SQLAlchemy
#from app import app

db = SQLAlchemy()

#Models

class Users(db.Model):
    __tablename__ = 'Users'

    userid = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String, nullable=False)
    lastname = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String(300), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    group = db.Column(db.String(120))
    create_date = db.Column(db.DateTime(timezone=True))

    