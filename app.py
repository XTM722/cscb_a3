# CSCB20 - Introduction to Web & Databases
"""
@author: Kevin A. Hou Zhong, Xu Yue, Siming Wu
@date: 2025-03-30
"""
from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = 'CSCB20_A3_SECRET_KEY'  # Session secret key

# Database config - SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assignment3.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and bcrypt
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) # User ID primary key
    full_name = db.Column(db.String(150), nullable=False) # Full name
    username = db.Column(db.String(150), unique=True, nullable=False) # Username
    password = db.Column(db.String(200), nullable=False) # Password
    role = db.Column(db.String(20), nullable=False)  # student or instructor

# route: homepage (index.html) only accessible when logged in
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('index.html', name=session.get('user_username'))

# route login page (auth.html) - GET: show login form, POST: process login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_username'] = user.username
            session['user_role'] = user.role
            flash(f"Welcome back, {user.username}!", 'success')
            return redirect('/')
        else:
            flash("Incorrect username or password.", 'danger')
            return redirect('/login')

    return render_template('auth.html')

# Route: Registration
@app.route('/register', methods=['POST'])
def register():
    full_name = request.form['full_name']
    username = request.form['username']
    password = request.form['password']
    confirm = request.form['confirm']
    role = request.form['role']

    if password != confirm:
        flash("Passwords do not match.", 'warning')
        return redirect('/login')

    if User.query.filter_by(username=username).first():
        flash("Username already taken.", 'info')
        return redirect('/login')

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(full_name=full_name, username=username, password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    flash("Registration successful! Please log in.", 'success')
    return redirect('/login')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", 'info')
    return redirect('/login')

# Protected routes: Must log in to access
@app.route('/syllabus')
def syllabus():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('syllabus.html')

@app.route('/assignments')
def assignments():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('assignments.html')

@app.route('/labs')
def labs():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('labs.html')

@app.route('/lecture_notes')
def lecture_notes():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('lecture_notes.html')

@app.route('/feedback')
def feedback():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('feedback.html')

@app.route('/course_team')
def course_team():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('course_team.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the DB file if it doesn't exist
    app.run(debug=True)
