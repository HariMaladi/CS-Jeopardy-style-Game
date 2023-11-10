from asyncio.windows_events import NULL
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import get_flashed_messages
from flask import jsonify
import requests
from datetime import datetime
import random
import string
from flask import make_response
from io import BytesIO
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import request
import platform
from flask import Flask, render_template, request, url_for, redirect, Blueprint, send_from_directory
from flask_wtf import FlaskForm
from wtforms.fields import StringField, SubmitField
from wtforms.validators import DataRequired
import os
from login import login_check as lc
from register import register_on_submit as rs

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    dob_year = db.Column(db.Integer, nullable=False)
    question1 = db.Column(db.String(255), nullable=False)
    answer1 = db.Column(db.String(255), nullable=False)
    question2 = db.Column(db.String(255), nullable=False)
    answer2 = db.Column(db.String(255), nullable=False)
    platform_name = db.Column(db.String(100), nullable=False)
    lastloggedin = db.Column(db.DateTime, nullable=True)

    def __init__(self, username,email, password, dob_year, question1, answer1, question2, answer2,platform_name,lastloggedin):
        self.username = username
        self.email = email
        self.password = password
        self.dob_year = dob_year
        self.question1 = question1
        self.answer1 = answer1
        self.question2 = question2
        self.answer2 = answer2
        self.platform_name=platform_name
        self.lastloggedin=lastloggedin


# Initialize login manager
login_manager = LoginManager(app)
#db.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Simulated logged-in users
active_sessions = set()

@app.route('/')
def index():
    return render_template('landingpage.html')

#face authentication

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    url = StringField('DataURL', validators=[])
    submit = SubmitField('LOGIN')

email = None
url = None

@app.route('/floginhome', methods=['GET', 'POST'])
def floginhome():
    global email, url
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        url = form.url.data
        return redirect(url_for('.flogin'))
    elif request.method == 'POST':
        form.email.data = email
        form.url.data = url
    return render_template('index.html', form=form)

@app.route('/fregister', methods=['GET', 'POST'])
def fregister():
    global email, url
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        url = form.url.data
        return redirect(url_for('.register_submit'))
    elif request.method == 'POST':
        form.email.data = email
        form.url.data = url
    return render_template('fregister.html', form=form)

@app.route('/flogin')
def flogin():
    global email, url
    if email == '' or url == '':
        return redirect(url_for('.floginhome'))
    if email == None or url == None:
        return redirect(url_for('.flogin'))
    status = lc(email, url)
    if status == "Image not clear! Please try again!":
        return render_template('fail.html', msg=status)
    if status == "Data does not exist!":
        return render_template('fail.html', msg=status)
    if status == "Successfully Logged in!":
        app.logger.info("Login Success")
        return render_template('fsuccess.html', msg=status)
    else:
        app.logger.info("Login Fail")
        return render_template('fail.html', msg=status)

@app.route('/register_submit')
def register_submit():
    global email, url
    if email == '' or url == '':
        return redirect(url_for('.fregister'))
    if email == None or url == None:
        return redirect(url_for('.register_submit'))
    status = rs(email, url)
    if status == "Registration Successful!":
        app.logger.info("Registration Success")
        return render_template('fsuccess.html', msg=status)
    else:
        app.logger.info("Registration fail")
        return render_template('fail.html', msg=status)




@app.route('/success')
@login_required
def success():
    response = make_response(render_template('success.html'))
    
    # Set cache control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/ulogin')
def ulogin():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    access_key = '9280db28627edad05e6803dfc81552d3'
    url = f'http://api.ipstack.com/check?access_key={access_key}'

    response = requests.get(url)
    data = response.json()
    print(data)
    platform_name = data.get('zip')
    address = data.get('city')
    print(platform_name)
    if user and check_password_hash(user.password, password):
        if user.platform_name != platform_name:
            address=''
            send_login_email(user.username, user.email,address)
            flash(('Login failed. You are not allowed to login from a different IP address.', 'error'))
            return redirect(url_for('index'))
        # Update lastloggedin column with current date and time
        user.lastloggedin = datetime.now()  # Set lastloggedin to current date and time
        db.session.commit()  # Commit the change to the database
        print(user.username, user.email)
        login_user(user, remember=True)
        send_login_email(user.username, user.email,address)
        flash(('Login successful', 'success'))
        return redirect(url_for('success'))
    else:
        flash(('Login failed. Please check your credentials.', 'error'))

    return redirect(url_for('index'))

def send_login_email(username, email,address):
    # Configure the email content
    if address == '':
        subject = f'Hello {username}, Login Unsuccessful, Because your accessing from different location'
    else:
        subject = f'Hello {username}, Login Successful and your location is {address}'
    message = f"Hello {username}, your login was successful at {datetime.now()}."

    # Set up the SMTP server and send the email
    from_email = 'srinivasmarella733@gmail.com'
    smtp_server = 'smtp.gmail.com'  # Use the correct SMTP server hostname
    smtp_port = 587
    smtp_username = 'prasadmp151@gmail.com'
    smtp_password = 'yodxyqyrcfzqpppm'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(from_email, email, msg.as_string())
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Error sending email:", str(e))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email=request.form['email']
        password = request.form['password']
        dob_year = request.form['dob_year']
        question1 = request.form['question1']
        answer1 = request.form['answer1']
        question2 = request.form['question2']
        answer2 = request.form['answer2']

        access_key = '9280db28627edad05e6803dfc81552d3'
        url = f'http://api.ipstack.com/check?access_key={access_key}'

        response = requests.get(url)
        data = response.json()
        lastloggedin=datetime.now()
        platform_name = data.get('zip')

        print(platform_name)
        # Create a new User instance with the provided data
        new_user = User(username=username,email=email, password=generate_password_hash(password), dob_year=dob_year,
                        question1=question1, answer1=answer1, question2=question2, answer2=answer2,platform_name=platform_name,lastloggedin=lastloggedin)
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        
        flash(('Registration successful. You can now login.', 'success'))
        return redirect(url_for('index'))
    
    return render_template('register.html', platform_name=platform.node())


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        
        user = User.query.filter_by(username=username).first()
        if user:
            if user.question1 and user.question2:  # Check if secret questions are available
                secret_questions = [user.question1, user.question2]
                return render_template('forgot_password.html', secret_questions=secret_questions, username=username)
            else:
                # Secret questions are not available, handle accordingly (e.g., show an error message)
                flash('Secret questions are not available for this user', 'error')
                return redirect(url_for('forgot_password'))
        else:
            flash('Username not found', 'error')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')


@app.route('/verify_secret_question', methods=['POST'])
def verify_secret_question():
    username = request.form['username']
    question = request.form['question']
    answer = request.form['answer']
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.question1 == question and user.answer1 == answer:
        return redirect(url_for('reset_password', username=username))
    elif user and user.question2 == question and user.answer2 == answer:
        return redirect(url_for('reset_password', username=username))
    else:
        flash('Invalid answer to secret question', 'error')
        return redirect(url_for('forgot_password'))



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password', username=username))
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            user.password=generate_password_hash(new_password)
            db.session.commit()
            flash('Password reset successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('User not found', 'error')
            return redirect(url_for('index'))
    
    username = request.args.get('username')
    if username is None:
        flash('Invalid request', 'error')
        return redirect(url_for('index'))
    
    return render_template('reset_password.html', username=username)







if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
