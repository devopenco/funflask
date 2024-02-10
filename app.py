import os
import sys
import click
from typing import List
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user


class Base(DeclarativeBase):
    pass


WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager(app)
# login_manager.login_view = 'login'

db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(20))
    username: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    blocked: Mapped[str] = mapped_column(String(1))
    password_hash: Mapped[str] = mapped_column(String(128))
    channels: Mapped[List['Channel']] = relationship(back_populates="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_blocked(self, flag):
        self.blocked = flag

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_superadmin(self, ):
        return 'Admin' == self.name

    def __init__(self, username, name='', blocked='0'):
        self.name = name
        self.username = username
        self.blocked = blocked


class Channel(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(60))
    url: Mapped[str] = mapped_column(String(120))
    author: Mapped[str] = mapped_column(String(20))
    user_id: Mapped[int] = mapped_column(ForeignKey('user.id'))
    user: Mapped["User"] = relationship(back_populates="channels")

    def __init__(self, title, url, author, user_id):
        self.title = title
        self.url = url
        self.author = author
        self.user_id = user_id


@app.cli.command()
@click.option('--drop', is_flag=True, help='Create after drop.')
def initdb(drop):
    """Initialize the database"""
    if drop:
        db.drop_all()
    db.create_all()
    click.echo('Initialized database.')


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        url = request.form.get('url')

        channel = Channel(title=title, author=author, url=url, user_id=current_user.id)
        db.session.add(channel)
        db.session.commit()
        flash('Channel added.')
        return redirect(url_for('index'))

    if current_user.is_authenticated:
        if current_user.name == 'Admin':
            channels = Channel.query.all()
        else:
            channels = Channel.query.where(Channel.user_id == current_user.id).all()
    else:
        # channels = Channel.query.all()
        channels = db.session.query(Channel).join(User).filter(User.blocked == '0').all()

    return render_template('index.html', channels=channels)


@app.route('/channel/edit/<int:channel_id>', methods=['GET', 'POST'])
@login_required
def edit(channel_id):
    channel = Channel.query.get_or_404(channel_id)
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        url = request.form.get('url')

        channel.title = title
        channel.author = author
        channel.url = url
        db.session.commit()
        flash('Item updated')
        return redirect(url_for('index'))

    return render_template('edit.html', channel=channel)


@app.route('/channel/delete/<int:channel_id>', methods=['POST'])
@login_required
def delete(channel_id):
    channel = Channel.query.get_or_404(channel_id)
    db.session.delete(channel)
    db.session.commit()
    flash('Item deleted')
    return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
    user = User.query.first()
    return render_template('404.html', uesr=user), 404


# @app.context_processor
# def inject_user():
#     user = User.query.first()
#     return dict(user=user)

# account


@login_manager.user_loader
def load_user(user_id):
    # user = User.query.get(int(user_id))
    user = db.session.get(User, int(user_id))
    return user


@app.cli.command()
@click.option('--username', prompt=True, help='The username used to login.')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='The password used to login.')
def admin(username, password):
    """Create Super Admin"""
    db.create_all()
    user = User.query.where(User.username == username).first()
    if user is not None:
        click.echo('Updating super admin...')
        user.username = username
        user.set_password(password)
    else:
        click.echo('Creating super admin...')
        user = User(username=username, name='Admin')
        user.set_password(password)
        db.session.add(user)

    db.session.commit()
    click.echo('Done.')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        if not username or not password1 or not password2:
            flash('Invalid input.')
            return redirect(url_for('register'))
        if not password1 == password2:
            flash('The passwords entered twice are different')
            return redirect(url_for('register'))

        _user = User.query.where(User.username == username).first()
        if _user is not None:
            flash('Username already exists')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password1)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully')
        return redirect(url_for('login'))

    return render_template('register.html')


# 超管禁用个人用户
@app.route('/setting', methods=['GET'])
@login_required
def setting():
    users = User.query.where(User.name != 'Admin').all()
    return render_template('setting.html', users=users)


@app.post('/setting/<int:cid>')
def block(cid):
    blocklist = request.form.get('blocklist', '').split(',')
    for username in blocklist:
        User.query.filter(User.username == username, User.name != 'Admin').update({'blocked': cid})
    db.session.commit()
    flash('User blocked successfully')
    return redirect(url_for('setting'))


# 用户修改用户名及密码
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        password = None
        if password1 is not None and password2 is not None:
            if not password1 == password2:
                flash('The passwords entered twice are different')
                return redirect(url_for('profile'))
            else:
                password = password1

        _user = User.query.filter(User.username == username, User.id != current_user.id).first()
        if _user is not None:
            flash('Username already exists')
            return redirect(url_for('profile'))

        current_user.username = username
        if password is not None:
            current_user.set_password(password)

        db.session.commit()
        flash('profile updated')
        return redirect(url_for('index'))

    return render_template('profile.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Invalid input.')
            return redirect(url_for('login'))
        user = User.query.where(User.username == username).first()
        if user is not None and user.validate_password(password):
            if user.blocked == '1':
                flash('You are blocked')
                return redirect(url_for('index'))
            login_user(user)
            flash('Login success')
            return redirect(url_for('index'))

        flash('Invalid username or password.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Goodbye.')
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
