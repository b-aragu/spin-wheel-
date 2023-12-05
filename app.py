from flask import Flask, render_template, redirect, url_for, request, flash, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import secrets
import logging
from datetime import datetime
import random 

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Updated secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Enable CORS for specific origins
CORS(app)

# Set up Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login route

# Define the User model with UserMixin for Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    chosen_by = db.relationship('Pairing', foreign_keys='Pairing.chosen_id', backref='chosen_user', lazy='dynamic')

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Pairing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chooser_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    chosen_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Email already exists. Please use a different email or log in.', 'error')
        else:
            new_user = User(name=name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            # User found, check password
            if user.verify_password(password):
                login_user(user)
                flash(f'Welcome back, {user.name}! Login successful!', 'success')
                return redirect(url_for('user'))
            else:
                flash('Incorrect password. Please try again.', 'error')
        else:
            flash('User not found. Please register or check the email.', 'error')

    return render_template('login.html')

@app.route('/user')
@login_required
def user():
    return redirect(url_for('wheel'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logging.error(f"Internal Server Error: {error}")
    return render_template('500.html'), 500

@app.route('/wheel')
@login_required
def wheel():
    users = User.query.all()
    num_segments = len(users)
    return render_template('wheel.html', users=users, num_segments=num_segments)

@app.route('/spin_wheel', methods=['POST'])
@login_required
def spin_wheel():
    selected_user_id = spin_the_wheel(current_user.id)

    if selected_user_id is not None:
        try:
            # Check if the selected person has already been chosen
            if Pairing.query.filter_by(chooser_id=current_user.id).first():
                flash('You have already made a selection. Please wait for others.', 'error')
            else:
                # Update the database with the new Secret Santa pairing
                new_pairing = Pairing(chooser_id=current_user.id, chosen_id=selected_user_id)
                db.session.add(new_pairing)
                db.session.commit()
                flash(f'You selected {User.query.get(selected_user_id).name}!', 'success')
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during database commit: {e}")
        finally:
            db.session.remove()
    else:
        # Handle the case when there is only one user
        # Display a message or redirect as needed
        flash('Not enough users for Secret Santa. Please invite more participants.', 'error')

    return redirect(url_for('wheel'))

def spin_the_wheel(chooser_id):
    available_users = User.query.filter(User.id != chooser_id).all()

    # Check if the chooser has already chosen someone
    chosen_pairing = Pairing.query.filter_by(chooser_id=chooser_id).first()
    if chosen_pairing:
        available_users = [user for user in available_users if user.id != chosen_pairing.chosen_id]

    # Check if there are at least two available users
    if len(available_users) < 2:
        flash('Not enough users for Secret Santa. Please invite more participants.', 'error')
        return None  # or handle the situation in another way

    chosen_user = random.choice(available_users)
    return chosen_user.id

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)

