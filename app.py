import dateutil.parser
import babel
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, flash, redirect, url_for
from flask_cors import CORS
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_migrate import Migrate
from logging import Formatter, FileHandler
from forms import *
from models import setup_db, db, Group_Permissions, Role_Permissions, Roles, Groups, User_Roles, Users, User_Groups, Permissions
from datetime import datetime, timezone
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
import sys

# migrate = Migrate(app, db)
def create_app():
    app = Flask(__name__)
    setup_db(app)
    login_manager = LoginManager()
    login_manager.session_protection = "strong"
    login_manager.login_view = "login"
    login_manager.init_app(app)

    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.after_request
    def after_request(response):
        response.headers.add(
            "Access-Control-Allow-Headers", "Content-Type,Authorization,true"
        )
        response.headers.add(
            "Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS"
        )
        return response

    def format_datetime(value, format='medium'):
        date = dateutil.parser.parse(value)
        if format == 'full':
            format="EEEE MMMM, d, y 'at' h:mma"
        elif format == 'medium':
            format="EE MM, dd, y h:mma"
        return babel.dates.format_datetime(date, format, locale='en')

    app.jinja_env.filters['datetime'] = format_datetime

    # Routes

    @app.route('/login', methods=['GET'])
    def login():
        username = request.form.get('username', None)
        password = request.form.get('password', None)

        try: 
            user = get_user_details(username)
            if not user or not check_password_hash(user.password, password):
                flash('Invalid password, please check password and try again!')
                return redirect('/login')

        except:
            flash('Please verify your login username and try again.')
            return redirect('/login')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect('/login')

    @app.route('/users/add', methods=['POST'])
    @login_required
    def add_new_user():
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'add_new_user')
        if isValid:
            try:
                username = request.form.get('username', None)
                user = get_user_details(username)
                if user:
                    flash('Username already exists')
                    return redirect(url_for('login'))
                firstname = request.form.get('firstname', None)
                lastname = request.form.get('lastname', None)
                email = (((firstname.lower()).split(" "))[0])+'.'+(((lastname.lower()).split(" "))[0])+'@idealab.com'
                password = ((username.lower()).split(" "))[0] + '2022'
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
                firstname = request.form.get('firstname')
                create_date = datetime.now()

                new_user = Users(username=username, firstname=firstname, lastname=lastname,email=email,password=hashed_password,create_date=create_date,created_by=current_user)
                db.session.add(new_user)
                db.session.commit()
                flash('User created successfully.')
                return redirect(url_for("login"))
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/users/<int:userid>', methods=['DELETE'])
    @login_required
    def delete_user(userid):
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'delete_user')
        if isValid:
            try:
                user = Users.query.filter(Users.userid == userid).one_or_none()
                db.session.delete(user)
                db.session.commit()
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/users/<int:userid>', methods=['POST'])
    @login_required
    def retrieve_user_info(userid):
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'retrieve_user_info')
        if isValid:
            try:
                user = Users.query.filter(Users.userid == userid).first()
                return jsonify({
                    "success": True,
                    "firstname": user.firstname,
                    "lastname": user.lastname,
                    "username": user.username,
                    "email": user.email,
                    "created_by": user.created_by,
                    "create_date": user.create_date
                })
            except Exception as e:
                flash(e, "danger")
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/users/all', methods=['POST'])
    @login_required
    def retrieve_all_users():
        data = []
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'retrieve_all_users')
        if isValid:
            try:
                users = db.session.query(Users).order_by('userid').all()
                for user in users:
                    data.append({
                        "success": True,
                        "firstname": user.firstname,
                        "lastname": user.lastname,
                        "username": user.username,
                        "email": user.email,
                        "created_by": user.created_by,
                        "create_date": user.create_date
                    })
                return data
            except Exception as e:
                flash(e, "danger")
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/users/add/roles', methods=['POST'])
    @login_required
    def assign_user_roles():
        username = request.form.get('username', None)
        rolename = request.form.get('rolename', None)
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'assign_user_roles')
        if isValid:
            try:
                user = get_user_details(username)
                roleid = Roles.query.filter(Roles.rolename == rolename).first()
                new_user_role = User_Roles(userid=user.userid,roleid=roleid)
                db.session.add(new_user_role)
                db.session.commit()
                return redirect(url_for("login"))
        
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/users/add/groups', methods=['POST'])
    @login_required
    def assign_user_groups():
        username = request.form.get('username', None)
        groupname = request.form.get('groupname', None)
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'assign_user_groups')
        if isValid:
            try:
                user = get_user_details(username)
                groupid = Groups.query.filter(Groups.groupname == groupname).first()
                new_user_role = User_Groups(userid=user.userid,groupid=groupid)
                db.session.add(new_user_role)
                db.session.commit()
                return redirect(url_for("login"))
        
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/roles/add/permissions', methods=['POST'])
    @login_required
    def assign_role_permissions():
        rolename = request.form.get('rolename', None)
        permission_id = request.form.get('permission_id', None)
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'assign_role_permissions')
        if isValid:
            try:
                roleid = Roles.query.filter(Roles.rolename == rolename).first()
                new_role_perm = Role_Permissions(roleid=roleid,permission_id=permission_id)
                db.session.add(new_role_perm)
                db.session.commit()
                return redirect(url_for("login"))
        
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))

    @app.route('/groups/add/permissions', methods=['POST'])
    @login_required
    def assign_group_permissions():
        groupname = request.form.get('groupname', None)
        permission_id = request.form.get('permission_id', None)
        cur_user_perm = get_user_permissions(current_user.userid)
        isValid = has_permissions(cur_user_perm, 'assign_group_permissions')
        if isValid:
            try:
                groupid = Groups.query.filter(Groups.groupname == groupname).first()
                new_role_perm = Group_Permissions(groupid=groupid,permission_id=permission_id)
                db.session.add(new_role_perm)
                db.session.commit()
                return redirect(url_for("login"))
        
            except Exception as e:
                flash(e, "danger")
                db.session.rollback()
            finally:
                db.session.close()
        else:
            flash('You do not have the permission to perform this function!')
            return redirect(url_for("login"))


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
            group_perm = get_group_permissions(group.groupid)
            user_permssions.append(group_perm)

        for perm in user_permssions:
            p = get_permissions(perm.permission_id)
            permissions.append(p)

        return permissions

    def has_permissions(permissions, description):
        for p in permissions:
            if p.permission_description == description:
                return True
            else:
                return False

    return app

app = create_app()

if __name__ == '__main__':
    app.run()