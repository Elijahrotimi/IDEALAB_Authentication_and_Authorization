from crypt import methods
from distutils.log import error
import json
from unicodedata import name
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
from models import Group_Permissions, Role_Permissions, Roles, User_Roles, db, Users, User_roles, User_Groups, Permissions
from datetime import datetime, timezone
import sys

app = Flask(__name__)
moment = Moment(app)
app.config.from_object('config')
db.init_app(app)

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
