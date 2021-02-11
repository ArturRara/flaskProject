from flask import Flask, request, render_template, make_response, flash, request
from flask_wtf.csrf import CSRFProtect
import time
import re
from datetime import datetime
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies,
                                unset_jwt_cookies)
from hashlib import sha256
import psycopg2
from psycopg2 import connect
from exceptions import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

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
    loginAttempts = db.relationship('LoginAttempts', backref='user', lazy=True)

    def __init__(self, login, password, email):
        self.login = login
        self.password = password
        self.email = email


class Password(db.Model):
    __tablename__ = 'password'
    id = db.Column(db.Integer, primary_key=True)
    siteName = db.Column(db.String(50))
    login = db.Column(db.String(50))
    password = db.Column(db.LargeBinary)

    def __init__(self, siteName, login, password):
        self.siteName = siteName
        self.login = login
        self.password = password


class LoginAttempts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    successful = db.Column(db.Boolean())
    ip = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, user_id, successful, ip):
        self.user_id = user_id
        self.successful = successful
        self.ip = ip


db.create_all()
db.session.commit()


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
            if not ((re.match('^.{8,30}$', form['password'])) and
                    (re.match('^.{3,20}$', form['login'])) and
                    (form['password'] == repeted_password)):
                raise InvalidForm()
            checkStrength(form['password'])
            if User.query.filter_by(login=form['login']).first():
                raise LoginAlreadyUsed()
            if User.query.filter_by(email=form['email']).first():
                raise EmailAlreadyUsed()
            password = generate_password_hash(form['password'], method='sha256')
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
            password = request.form['password']
            if (re.match('^.{8,30}$', password)) and (re.match('^.{3,30}$', login)):
                user = User.query.filter_by(login=login).first()
                ip = request.remote_addr
                if user:
                    if check_password_hash(user.password, password):
                        key = PBKDF2(password, user.email, 1000).decode('utf-8', "replace")[:16]
                        access_token = create_access_token(identity={"login": login, "masterPbk": key})
                        userPasswords = Password.query.filter_by(login=login).all()
                        resp = make_response(render_template('passwords.html', userPasswords=userPasswords))
                        set_access_cookies(resp, access_token, max_age=600)
                        new_user = LoginAttempts(user_id=user.id, successful=True, ip=ip)
                        db.session.add(new_user)
                        db.session.commit()
                        return resp
                    else:
                        new_user = LoginAttempts(successful=False, ip=ip, user_id=user)
                        db.session.add(new_user)
                        db.session.commit()
                        raise InvalidForm()
                else:
                    raise InvalidForm()
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
        if form['password']:
            password = form['password']
        else:
            password = generatePassword(User.query.filter_by(login=get_jwt_identity()["login"]).first().password,
                                        form['siteName'])
        password = encrypt_data(password, get_jwt_identity()["masterPbk"])
        newPassword = Password(siteName=form['siteName'], login=get_jwt_identity()["login"], password=password)
        db.session.add(newPassword)
        db.session.commit()
    userPasswords = Password.query.filter_by(login=get_jwt_identity()["login"]).all()
    if userPasswords:
        return render_template('passwords.html', form=form, userPasswords=userPasswords)
    return render_template('passwords.html', form=form)


@app.route('/passwordsGet/<string:siteName>', methods=['GET', 'POST'])
@jwt_required
def passwordsGet(siteName):
    password = Password.query.filter_by(login=get_jwt_identity()["login"], siteName=siteName).first()
    flash(decrypt_data(password.password, get_jwt_identity()["masterPbk"]), category=siteName)
    userPasswords = Password.query.filter_by(login=get_jwt_identity()["login"]).all()
    return render_template('passwords.html', userPasswords=userPasswords)


@app.route('/loginAttempts')
@jwt_required
def loginAttempts():
    user = User.query.filter_by(login=get_jwt_identity()["login"]).first()
    loginAttempts = sorted(user.loginAttempts,
                           key=lambda a: a.date, reverse=True)
    time_format = r'%d/%m/%Y %H:%M:%S'
    loginAttempts = [{'ip': a.ip, 'successful': a.successful, 'time': a.date.strftime(time_format)}
                     for a in loginAttempts[:10]]

    return render_template('loginAttempts.html', login_attempts=loginAttempts)


def checkStrength(password):
    if (len(password) >= 8):
        if (bool(re.match(r'[A-Za-z0-9@#$%^&+=]{8,20}', password)) == True):
            print('The password is strong')
        else:
            raise WeakPassword('Haslo powinno zawierac male i wielkie litery,cyfry i znaki specjalne')
    else:
        raise WeakPassword('Haslo musi zawierac conajmniej 8 znakow')


def generatePassword(masterpass, site):
    key = site + masterpass
    pswd = key
    for i in range(1, 250):
        pswd = sha256(pswd.encode('utf-8')).hexdigest()
    pswd = pswd[:12]

    return pswd


def encrypt_data(password, master_pass):
    key = master_pass.encode("utf-8")

    iv = Random.new().read(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_to_encrypt = password.encode("utf-8")
    padded_data = pad(data_to_encrypt, 16)
    encrypted_data = cipher.encrypt(padded_data)
    x = iv + encrypted_data
    print(x)

    return x


def decrypt_data(password, master_pass):
    print(password)
    print(master_pass)

    iv = password[:16]

    key = master_pass.encode("utf-8")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_password = unpad(cipher.decrypt(password[16:]), 16).decode("utf-8")

    return plaintext_password


if __name__ == '__main__':
    app.run(debug=True)
