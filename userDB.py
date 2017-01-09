from datetime import datetime
from sqlalchemy import *
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, Integer, DATETIME, VARCHAR, BOOLEAN
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash


"""engine = create_engine('mysql+mysqlconnector://root:@localhost/blog', echo=True)"""
engine = create_engine('mysql+mysqlconnector://root:@localhost/test', echo=True)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    """
    id = Column('used_id', Integer, primary_key=true)
    username = Column('username', VARCHAR(20), unique=True, index=True)
    password = Column('password', VARCHAR(250))
    email = Column('email', VARCHAR(50), unique=True, index=True)
    registred_on = Column('registred_on', DATETIME)


    def __init__(self, username, password,  email):
        self.username = username
        self.set_password(password)
        self.email = email
        self.registred_on = datetime.utcnow()
    """

    id = Column('used_id', Integer, primary_key=true)
    username = Column('username', VARCHAR(20), unique=True, index=True)
    password = Column('password', VARCHAR(250))
    email = Column('email', VARCHAR(50), unique=True, index=True)
    registred_on = Column('registred_on', DATETIME)
    confirmed = Column('confirmed', BOOLEAN, nullable=False, default=False)
    confirmed_on = Column('confirmed_on', DATETIME, nullable=True)

    def __init__(self, username, password, email, confirmed, confirmed_on=None):
        self.username = username
        self.set_password(password)
        self.email = email
        self.registred_on = datetime.utcnow()
        self.confirmed = confirmed
        self.confirmed_on = confirmed_on

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return False

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<User %r' % self.username

Base.metadata.create_all(engine)
