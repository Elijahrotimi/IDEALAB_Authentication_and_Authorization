from flask_sqlalchemy import SQLAlchemy
#from app import app
from flask_login import UserMixin

db = SQLAlchemy()
migrage = Migrate()

#Models

class Users(UserMixin, db.Model):
    __tablename__ = 'Users'

    userid = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String, nullable=False)
    lastname = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String(300), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    created_by = db.Column(db.String(120), nullable=False, unique=True)
    create_date = db.Column(db.DateTime(timezone=True))
    roles = db.relationship('User_Roles', backref='Users', lazy='dynamic')
    groups = db.relationship('User_Groups', backref='Users', lazy='dynamic')

class Roles(db.Model):
    __tablename__ = 'Roles'
    roleid = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String, nullable=False)
    users = db.relationship('User_Roles', backref='Roles', lazy='dynamic')
    permissions = db.relationship('Role_Permissions', backref='Roles', lazy='dynamic')
    
class Groups(db.Model):
    __tablename__ = 'Groups'
    groupid = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String, nullable=False)
    users = db.relationship('User_Groups', backref='Groups', lazy='dynamic')
    permissions = db.relationship('Group_Permissions', backref='Groups', lazy='dynamic')

class Permissions(db.Model):
    __tablename__ = 'Permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    permission_description = db.Column(db.String(120), nullable=False)
    resource_url = db.Column(db.String(120), nullable=False)
    roles = db.relationship('Role_Permissions', backref='Permissions', lazy='dynamic')
    groups = db.relationship('Group_Permissions', backref='Permissions', lazy='dynamic')

class User_Roles(db.Model):
    __tablename__ = 'User_Roles'
    user_role_id = db.Column(db.Integer, primary_key=True)
    roleid = db.Column(db.Integer, db.ForeignKey('Roles.roleid'), nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('Users.userid'), nullable=False)

class User_Groups(db.Model):
    __tablename__ = 'User_Groups'
    user_group_id = db.Column(db.Integer, primary_key=True)
    groupid = db.Column(db.Integer, db.ForeignKey('Groups.groupid'), nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('Users.userid'), nullable=False)

class Role_Permissions(db.Model):
    __tablename__ = 'Role_Permissions'
    role_permission_id = db.Column(db.Integer, primary_key=True)
    roleid = db.Column(db.Integer, db.ForeignKey('Roles.roleid'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('Permissions.permission_id'), nullable=False)

class Group_Permissions(db.Model):
    __tablename__ = 'Group_Permissions'
    group_permission_id = db.Column(db.Integer, primary_key=True)
    groupid = db.Column(db.Integer, db.ForeignKey('Groups.groupid'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('Permissions.permission_id'), nullable=False)


