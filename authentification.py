from flask import Flask, session, request, flash, url_for, redirect, render_template, abort ,g
from flask_login import login_user, login_required, current_user, logout_user
from flask_login import LoginManager
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from userDB import *

engine = create_engine('mysql+mysqlconnector://root:@localhost/blog', echo=True)

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'


login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'


@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    user = User(request.form['username'], request.form['password'], request.form['email'])
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(user)
    s.commit()
    flash('User successfully registred')
    return redirect(url_for('login'))


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

    if registered_user is None:
        flash('Username or Password is invalid', 'error')
        return redirect(url_for('login'))
    if not registered_user.check_password(password):
        flash('Password is invalid', 'error')
        return redirect(url_for('login'))
    login_user(registered_user, remember=remember_me)
    flash('Logged in successfully')
    return redirect(request.args.get('next') or url_for('index'))


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


if __name__ == '__main__':
    app.run()
