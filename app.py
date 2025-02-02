from flask import Flask, render_template, request, redirect, url_for, session, flash
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    username = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(50))
    password = db.Column(db.String(100))
    
    def __init__(self,email,password,username):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))
    
    def get_id(self):
        return self.username 

class Diary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    diary_data = db.Column(db.Text)
    created_by = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)
    date_created = db.Column(db.DateTime, server_default=db.func.now())

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(username):
    return User.query.get(username)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect('/register')
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('user sucessfully created', 'success')
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if fields are empty
        if not username or not password:
            return "Please fill in all fields", 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        # If the user doesn't exist or password doesn't match
        flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == 'POST':
        write_data = request.form['diary_data']
        if not write_data.strip():
            flash('Diary cannot be empty', 'danger')
            return redirect(url_for('create'))
        diary_db = Diary(diary_data=write_data, created_by=current_user.username, date_created=db.func.now())
        db.session.add(diary_db)
        db.session.commit()
        flash(Markup(f'Diary created successfully! <a href="{url_for("your_diary")}" class="flash-link">View Diary</a>'), 'success')
    return render_template('create.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user = current_user)

@app.route('/your_diaries')
@login_required
def your_diary():
    diaries = Diary.query.filter_by(created_by=current_user.username).all()
    return render_template('your_diaries.html', diaries=diaries)

@app.route('/diary/user/<username>/<int:diary_id>')
@login_required
def diary(username, diary_id):
    diary = Diary.query.filter_by(id=diary_id, created_by=username).first()
    if diary and diary.created_by == current_user.username:
        return render_template('diary.html', diary=diary)
    return "Diary not found", 404

@app.route("/friends")
@login_required
def friends():
    return render_template('friends.html')

if __name__ == '__main__':
    app.run(debug=True)
