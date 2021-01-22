from flask import Flask, request, render_template, make_response, flash
from flask_wtf.csrf import CSRFProtect
import time
import re
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies,
                                unset_jwt_cookies)
from hashlib import sha256
import psycopg2
from psycopg2 import connect
from exceptions import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
app = Flask(__name__)

# csrf = CSRFProtect(app)


app.config['JWT_TOKEN_LOCATION'] = 'cookies'
app.config['SECRET_KEY'] = 'mysecretkeybutlonger'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 600
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
jwt = JWTManager(app)

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user='postgres', pw='superuser', url='localhost:5432',
                                                               db='postgres')
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.create_all()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    email = db.Column(db.String(50), unique=True)

    def __init__(self, login, password, email):
        self.login = login
        self.password = password
        self.email = email


class Password(db.Model):
    __tablename__ = 'password'
    id = db.Column(db.Integer, primary_key=True)
    siteName = db.Column(db.String(50))
    login = db.Column(db.String(50))
    password = db.Column(db.String(200))

    def __init__(self, siteName, login, password):
        self.siteName = siteName
        self.login = login
        self.password = password



@app.route('/')
def index():
    return render_template('login.html')


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        time.sleep(2)
        try:
            form = request.form
            repeted_password = request.form['repeat-password']
            if not((re.match('^.{8,30}$', form['password'])) and
                    (re.match('^.{3,20}$', form['login'])) and
                    (form['password'] == repeted_password)):
                raise InvalidForm()
            checkStrength(form['password'])
            if User.query.filter_by(login=form['login']).first():
                raise LoginAlreadyUsed()
            if User.query.filter_by(email=form['email']).first():
                raise EmailAlreadyUsed()
            password = generate_password_hash(form['password'], method='sha256')
            print(form['login'])
            new_user = User(login=form['login'], password=password, email=form['email'])
            db.session.add(new_user)
            db.session.commit()
            response = make_response(render_template('login.html'))
            return response
        except LoginAlreadyUsed:
            flash('Login juz wykorzystany')
            return render_template('registration.html')
        except EmailAlreadyUsed:
            flash('Email juz wykorzystany')
            return render_template('registration.html')
        except InvalidForm:
            flash('Podano bledne dane w formularzu')
            return render_template('registration.html')
        except WeakPassword:
            flash('Haslo musi miec conajmniej 8 liter, zawierac małe i duze litery,cyfry, oraz znaki specjalne')
            return render_template('registration.html')

    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        time.sleep(2)
        try:
            login = request.form['login']
            print(login)
            password = request.form['password']
            if (re.match('^.{8,30}$', password)) and (re.match('^.{3,30}$', login)):
                user = User.query.filter_by(login=login).first()
                if not user or not check_password_hash(user.password, password):
                    raise InvalidForm()

                access_token = create_access_token(identity=login)
                userPasswords = Password.query.filter_by(login=login).all()
                resp = make_response(render_template('passwords.html', userPasswords=userPasswords))
                set_access_cookies(resp, access_token, max_age=600)
                return resp
            else:
                raise InvalidCharacters()
        except InvalidForm:
            flash('Bledny login lub haslo')
            return render_template('login.html')
        except InvalidCharacters:
            flash('Niepoprawne dane logowania')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required
def logout():
    response = make_response(render_template('login.html'))
    unset_jwt_cookies(response)
    return response


@app.route('/passwords', methods=['GET', 'POST'])
@jwt_required
def passwords():
    form = request.form
    if request.method == 'POST':
        print(form)
        if form['password']:
            password = form['password']
        else:
            password = generatePassword(User.query.filter_by(login=get_jwt_identity()).first().password, form['siteName'])
        newPassword = Password(siteName=form['siteName'], login=get_jwt_identity(), password=password)
        db.session.add(newPassword)
        db.session.commit()
    userPasswords = Password.query.filter_by(login=get_jwt_identity()).all()
    if userPasswords:
        return render_template('passwords.html', form=form, userPasswords=userPasswords)
    return render_template('passwords.html', form=form)


@app.route('/passwordsGet/<string:siteName>', methods=['GET', 'POST'])
@jwt_required
def passwordsGet(siteName):
    password = Password.query.filter_by(login=get_jwt_identity(), siteName=siteName).first()
    flash(password.password, category=siteName)
    userPasswords = Password.query.filter_by(login=get_jwt_identity()).all()
    return render_template('passwords.html', userPasswords=userPasswords)


if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()


def checkStrength(password):
    if (len(password) >= 8):
        if (bool(re.match(r'[A-Za-z0-9@#$%^&+=]{8,20}', password)) == True):
            print('The password is strong')
        else:
            raise WeakPassword('Haslo powinno zawierac male i wielkie litery,cyfry i znaki specjalne')
    else:
        raise WeakPassword('Haslo musi zawierac conajmniej 8 znakow')


def generatePassword(masterpass,site):
    key = site + masterpass
    pswd = key
    for i in range(1, 250):
        pswd = sha256(pswd.encode('utf-8')).hexdigest()
    pswd = pswd[:12]

    return pswd
