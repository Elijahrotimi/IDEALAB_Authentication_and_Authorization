from distutils.log import error
import json
import dateutil.parser
import babel
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, Response, flash, redirect, url_for
from flask_cors import CORS
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_migrate import Migrate
import logging
from logging import Formatter, FileHandler
from flask_wtf import Form
from forms import *
from models import Group_Permissions, Role_Permissions, Roles, Groups, User_Roles, db, Users, User_Groups, Permissions
from datetime import datetime, timezone
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
import sys

app = Flask(__name__)
moment = Moment(app)
app.config.from_object('config')
db.init_app(app)

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.init_app(app)

migrate = Migrate(app, db)


def format_datetime(value, format='medium'):
  date = dateutil.parser.parse(value)
  if format == 'full':
      format="EEEE MMMM, d, y 'at' h:mma"
  elif format == 'medium':
      format="EE MM, dd, y h:mma"
  return babel.dates.format_datetime(date, format, locale='en')

app.jinja_env.filters['datetime'] = format_datetime

# Routes

@app.after_request
def after_request(response):
    response.headers.add(
        "Access-Control-Allow-Headers", "Content-Type,Authorization,true"
    )
    response.headers.add(
        "Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS"
    )
    return response

#functions
def get_user_details(username):
    user = Users.query.filter(Users.username == username).first()
    return user

def get_user_roles(userid):
    roles = db.session.query(User_Roles).filter(User_Roles.userid==userid).all()
    return roles

def get_user_groups(userid):
    groups = db.session.query(User_Groups).filter(User_Groups.userid==userid).all()
    return groups

def get_role_permissions(roleid):
    permissions = db.session.query(Role_Permissions).filter(Role_Permissions.roleid==roleid).all()
    return permissions

def get_group_permissions(groupid):
    permissions = db.session.query(Group_Permissions).filter(Group_Permissions.roleid==groupid).all()
    return permissions

def get_permissions(permissionid):
    permission = db.session.query(Permissions).filter(Permissions.permission_id==permissionid)
    return permission

def get_user_permissions(userid):
    permissions = []
    user_permssions = []
    user_roles = get_user_roles(userid)
    user_groups = get_user_groups(userid)

    for role in user_roles:
        role_perm = get_role_permissions(role.roleid)
        user_permssions.append(role_perm)
    
    for group in user_groups:
        group_perm = get_group_permissions(user_groups.groupid)
        user_permssions.append(group_perm)

    for perm in user_permssions:
        p = get_permissions(perm.permission_id)
        permissions.append(p)

    return permissions