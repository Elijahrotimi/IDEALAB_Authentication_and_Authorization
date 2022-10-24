# IDEALAB_Authentication_and_Authorization

## Introduction

This is a module to demonstrate authentication and authorization of users in an organization.
The module authenticates against a database, using the username and password.

## Tech Stack (Dependencies)

The tech stack includes the following:
 * **virtualenv** as a tool to create isolated Python environments
 * **SQLAlchemy ORM** to be the ORM library
 * **PostgreSQL** as the database
 * **Python** and **Flask** as the server language and server framework
 * **Flask-Migrate** for creating and running schema migrations
You can download and install the dependencies mentioned above using `pip` as:
```
pip install virtualenv
pip install SQLAlchemy
pip install postgres
pip install Flask
pip install Flask-Migrate
```

## Main Files: Project Structure

  ```sh
  ├── README.md
  ├── app.py *** the main driver of the app. 
  ├── models.py *** Includes the SQLAlchemy models.
  ├── config.py *** Database URLs, CSRF generation, etc
  ├── manage.py *** To run tha pp
  ├── requirements.txt *** The dependencies we need to install with "pip3 install -r requirements.txt"
 
  ```

## Development Setup
1. **Download the project code locally**
```
git clone  https://github.com/Elijahrotimi/IDEALAB_Authentication_and_Authorization.git

```

2. **Initialize and activate a virtualenv using:**
```
python -m virtualenv env
source env/Scripts/activate
```

3. **Install the dependencies:**
```
pip install -r requirements.txt
```

4. **Create Database:**
```
dropdb Idealabdb
createdb Idealabdb
```
5. **Run the development server:**
```
export FLASK_APP=app.py
export FLASK_ENV=development
flask run --reload
```
