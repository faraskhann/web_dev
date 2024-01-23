from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
auth = Blueprint("auth", __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if check_password_hash(existing_user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(existing_user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email not found.', category='error')


    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Invalid email; Must be at least 4 characters.', category='error')
        elif len(firstName) < 2:
            flash('Invalid first name; Must be at least 2 characters.', category='error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters', category='error')
        elif password != password2:
            flash('Passwords do not match.', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(existing_user, remember=True)
            flash('Account Created!', category='success')
            return redirect(url_for('views.home'))
    return render_template("signup.html", user=current_user)

