from flask import Flask, request, jsonify, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy 
from flask_marshmallow import Marshmallow 
import os
import re
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import datetime


# Init app
app = Flask(__name__)

# Database Env settings
ENV = 'dev'

if ENV =='dev':
    app.secret_key='soft-text'
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:ginger@localhost:5432/soft_textdb' 
else:
    app.debug = False 
    app.config['SQLALCHEMY_DATABASE_URI'] = ''

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# init db
db = SQLAlchemy(app)
# init ma
ma = Marshmallow(app)


# Users Model 
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(14), nullable=False)
    username = db.Column(db.String(14), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    register_date = db.Column(db.DateTime(), default=datetime.utcnow)
    message = db.relationship('Message', backref='users', lazy=True)
    article = db.relationship('Article', backref='users', lazy=True)

    def __init__(self, firstname, lastname, country, email, phone, username, password):
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.country = country
        self.phone = phone
        self.email = email
        self.password = password
        

# User Schema
class UserSchema(ma.Schema):
    class Meta:
        # fileds to expose
        fields = ['id', 'firstname', 'lastname', 'country', 'email', 'phone', 'username', 'password', 'register_date']

# init Schema
User_schema = UserSchema()
Users_schema = UserSchema(many=True) 

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), unique=True)
    creator_id = db.Column(db.Integer(), db.ForeignKey("users.id"))
    body = db.Column(db.Text(), nullable=True)
    create_date = db.Column(db.DateTime(), default=datetime.utcnow)
    recipient = db.Column(db.ARRAY(db.String()), nullable=False)

    def __init__(self, subject, creator_id, body, create_date, recipient):
        self.subject = subject
        self.creator_id = creator_id
        self.body = body
        self.create_date = create_date
        self.recipient = recipient

# Message Schema
class MessageSchema(ma.Schema):
    class Meta:
        # fields to expose 
        fields = ["id", "subject", "creator_id", "body", "create_date"]

# Init Schema 
Message_schema = MessageSchema()
Messages_schema = MessageSchema(many=True)

# Role Model
class Roles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_type = db.Column(db.String, nullable=False)
    users = db.relationship('Users', backref='roles', lazy=True)

    def __init__(self, role_type):
        self.role_type = role_type
# Role Schema
class RoleSchema(ma.Schema):
    class Meta:
        fileds = ['id',"role_type"]

# Init Schema
Role_schema = RoleSchema()

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    author = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    content = db.Column(db.Text)
    creator_id = db.Column(db.Integer(), db.ForeignKey("users.id"))

    def __init__(self, title, author, date_posted, content):
        self.title
        self.author
        self.date_posted
        self.content


class ArticleSchema(ma.Schema):
    class Meta:
        fields = ["title","author","date_posted","content"]

# Init Schema 
Article_schema = ArticleSchema()
Articles_schema = ArticleSchema(many=True)


# Home 
@app.route('/', methods=['GET'])
def get():
    return render_template('home.html')

# About
@app.route('/about/')
def about():
    return render_template('about.html')

# Contact
@app.route('/contact/')
def contact():
    return render_template('contact.html')

# Register form class
class RegisterForm(Form):
    firstname = StringField('First Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    lastname = StringField('Last Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    username = StringField('Username', [validators.Length(min=4, max=25), validators.DataRequired()])
    country = StringField('Country', [validators.DataRequired()])
    email = StringField('Email', [validators.Length(min=6, max=50), validators.DataRequired()])
    phone = StringField('Contact', [validators.Length(min=1, max=50), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# User Register 
@app.route('/register/', methods=['GET','POST'])
def register():
    form=RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        firstname = form.firstname.data 
        lastname = form.lastname.data
        username = form.username.data
        country = form.country.data
        email = form.email.data
        phone = form.phone.data
        password = sha256_crypt.encrypt(str(form.password.data))
        #password = password.decode("utf-8", "ignore")


        new_user = Users(firstname, lastname, country, email, phone, username, password)

        db.session.add(new_user)
        db.session.commit()


        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# User Login
@app.route('/login/', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # get field 
        username = request.form['username']
        password_cadidate = request.form['password']

        result = Users.query.filter_by(username=username).all()

        

        if len(result) > 0:
            # get stored hash
            data = Users.query.filter_by(username=username).first()
            password = data.password

            # compare passwords
            if sha256_crypt.verify(password_cadidate, password):
                # passed
                session['logged_in'] = True
                session['username'] = username
                flash('You are now Logged in', 'success')
                return redirect(url_for('dashboard'))
            
            else:
                error = 'Invalid Login'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs): 
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now Logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    article = Article.query.order_by(Article.date_posted.desc()).all()

    if len(article) > 0:
        return render_template('dashboard.html', article=article)
    else:
        msg = "No Articles Found"
        return render_template('dashboard.html', msg=msg)

# Run Server
if __name__ == '__main__':
    app.run()