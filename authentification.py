from flask import Flask, session, request, flash, url_for, redirect, render_template, abort ,g
from flask_login import login_user, login_required, current_user, logout_user
from flask_login import LoginManager
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message, Mail
from userDB import *
from functools import wraps
import os

engine = create_engine('mysql+mysqlconnector://root:@localhost/test', echo=True)

app = Flask(__name__)

app.config.update(
    DEBUG=True,
    SECRET_KEY='7d441f27d441f27567d441f2b6176a',
    SECURITY_PASSWORD_SALT = 'my_precious_two',

    # mail settings
    MAIL_SERVER = 'smtp.googlemail.com',
    MAIL_PORT = 465,
    MAIL_USE_TLS = False,
    MAIL_USE_SSL = True,


    # mail accounts
    MAIL_USERNAME = 'martinmravec4@gmail.com',
    MAIL_PASSWORD = 'asdfghjkl123qwert'
)


login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'

mail = Mail(app)


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    user = User(request.form['username'], request.form['password'], request.form['email'], confirmed=False)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(user)
    s.commit()
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email."
    """
        Not work in tssk-proxy
    """
    """try:
        send_email(user.email, subject, html)
        login_user(user)

        flash('User successfully registred. A confirmation email has been sent via email.', 'success')
        return redirect(url_for('login'))
    except:
    """
    login_user(user)
    """
    return redirect(url_for("unconfirmed"))
    """
    return html


@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('This confirmation link is invalid or has expired.', 'danger')
    Session = sessionmaker(bind=engine)
    s = Session()
    user = s.query(User).filter_by(email=email).first()
    if user.confirmed:
        flash('Account allredy confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.utcnow()
        s.add(user)
        s.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('profile'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['username']
    password = request.form['password']

    remember_me = False
    if 'remember_me' in request.form:
        remember_me = True

    Session = sessionmaker(bind=engine)
    s = Session()
    registered_user = s.query(User).filter_by(username=username).first()
    confirmed_user = s.query(User).filter_by(confirmed=True).first()
    if confirmed_user is None:
        flash('Your account has not been activated yet.', 'error')
        return redirect(url_for('login'))
    if registered_user is None:
        flash('Username or Password is invalid', 'error')
        return redirect(url_for('login'))
    if not registered_user.check_password(password):
        flash('Password is invalid', 'error')
        return redirect(url_for('login'))
    login_user(registered_user, remember=remember_me)
    flash('Logged in successfully')
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect('login')
    flash('Please confirm your account!', 'warning')
    return render_template('unconfirmed.html')


def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.confirmed is False:
            flash('Please confirm your account!','warning')
            return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)

    return decorated_function


@app.route('/profile', methods=['GET', 'POST'])
@login_required
@check_confirmed
def profile():
    return render_template('profile.html')


@app.route('/navigation', methods=['GET', 'POST'])
@login_required
@check_confirmed
def navigation():
    return render_template('navigation.html')


@app.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url = confirm_url)
    subject = "Please confirm your email"
    """
    send_email(current_user.email, subject, html)
    """
    flash('A new confirmation email has been sent.', 'success')
    return html


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(id):
    Session = sessionmaker(bind=engine)
    s = Session()
    return s.query(User).get(int(id))


@app.before_request
def before_request():
    g.user = current_user
    if current_user is None:
        return render_template('login.html')


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_USERNAME']
    )
    mail.send(msg)


if __name__ == '__main__':
    app.run()
