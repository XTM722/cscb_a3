# CSCB20 - Introduction to Web & Databases
"""
@author: Kevin A. Hou Zhong, Xu Yue, Siming Wu
@date: 2025-03-30
"""
from flask import Flask, jsonify, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = 'CSCB20_A3_SECRET_KEY'  # Session secret key

# Database config - SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assignment3.db' # SQLite database file
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
    grades = db.relationship('Grade', backref='student', lazy= True) 

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key = True) # Grade ID primary key
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Foreign key to User
    category = db.Column(db.String(50), nullable=False) # Category of the grade
    mark = db.Column(db.Float, nullable = True)
    


motivational_messages = [
    "Keep pushing forward and make this semester count!",
    "Believe in yourself and all that you are capable of!",
    "Success is the sum of small efforts, repeated day in and day out.",
    "Your hard work and dedication will pay off!",
    "Stay focused and never give up on your dreams!",
    "Every day is a new opportunity to improve yourself.",
    "You are capable of achieving greatness!",
    "Embrace challenges as opportunities for growth.",
    "Your efforts today will lead to success tomorrow.",
]


# route: homepage (index.html) only accessible when logged in
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('user_role') == 'instructor':
        return redirect('/instructor')
    return render_template('index.html')

# route: instructor page (instructor.html) only accessible when logged in as instructor
@app.route('/instructor')
def instructor_dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('user_role') != 'instructor':
        return redirect('/instructor')
    
    # get instructor username from session
    user = User.query.get(session['user_id'])
    first_name = user.full_name.split()[0]  # Get first name
    return render_template('instructor_dashboard.html', name=first_name)

# route login page (auth.html) - GET: show login form, POST: process login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET' and 'user_id' in session:
        if session.get('user_role') == 'instructor':
            return redirect('/instructor')
        return redirect('/')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_username'] = user.username
            session['user_role'] = user.role
            first_name = user.full_name.split()[0]  # Get first name
            index = sum(ord(c) for c in user.username) % len(motivational_messages)  # Hash username to get index
            motivation = motivational_messages[index]  # Get motivational message
            session['login_msg'] = f"Welcome {first_name}! {motivation}" # store welcome message in session
            return redirect('/instructor' if user.role == 'instructor' else '/') 
        else:
            flash("Incorrect username or password.", 'danger')
            return redirect('/login')

    return render_template('auth.html')

# route: registration page (auth.html) - GET: show registration form, POST: process registration
@app.route('/register', methods=['POST'])
def register():
    full_name = request.form['full_name']
    username = request.form['username']
    password = request.form['password']
    confirm = request.form['confirm']
    role = request.form['role']

    
    # validation input
    if len(username) < 4 or len(username) > 20:
        flash("Username must be between 4 and 20 characters.", 'warning')
        return render_template('auth.html', show_register=True)
    
    if len(password) < 8 or len(password) >20:
        flash("Password must be between 8 and 20 characters.", 'warning')
        return render_template('auth.html', show_register=True)
    
    if len(full_name) < 4 or len(full_name) > 50:
        flash("Full name must be between 4 and 50 characters.", 'warning')
        return render_template('auth.html', show_register=True)
    
    if password != confirm:
        flash("Confirmation password do not match, Please try again!", 'warning')
        return render_template('auth.html', show_register=True)

    if User.query.filter_by(username=username).first():
        flash("Username is already taken. Plase try again!", 'info')
        return render_template('auth.html', show_register=True)

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(full_name=full_name, username=username, password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()

    flash("Registration successful! Please log in.", 'success')
    return redirect('/login')

# route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", 'info')
    return redirect('/login')

# protected routes: Must log in to access
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

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.route('/manage_marks', methods=['GET', 'POST'])
def manage_marks():
    if 'user_id' not in session or session.get('user_role') != 'instructor':
        return redirect('/login')

    students = User.query.filter_by(role='student').all()
    selected_student = None
    grades = []

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        category = request.form.get('category')
        mark = request.form.get('mark')

        if student_id and not category and not mark:
            # Just selected a student (via AJAX)
            selected_student = User.query.get(student_id)
            grades = Grade.query.filter_by(student_id=student_id).all()
            html = render_template('grades_fragment.html', selected_student=selected_student, grades=grades)
            return jsonify({'html': html})
        
        elif student_id and category and mark:
            selected_student = User.query.get(student_id)
            existing_grade = Grade.query.filter_by(student_id=student_id, category=category).first()
            if existing_grade:
                existing_grade.mark = mark
            else:
                db.session.add(Grade(student_id=student_id, category=category, mark=mark))
            db.session.commit()
            flash(f"Grade for {category} updated!", "success")
            grades = Grade.query.filter_by(student_id=student_id).all()
            html = render_template('grades_fragment.html', selected_student=selected_student, grades=grades)
            return jsonify({'html': html, 'message': 'Marks updated successfully!'})

    # Default GET
    return render_template(
        'manage_marks.html',
        students=students,
        selected_student=selected_student,
        grades=grades
    )
        

@app.route('/remark_request')
def remark_requests():
    return "Remark request page comming soon!"

@app.route('/instructor_feedback')
def instructor_feedback():
    return "Instructor feedback page comming soon!"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the DB file if it doesn't exist
    app.run(debug=True)

