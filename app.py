from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

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
    
    def get_id(self):
        return self.username

class Diary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    diary_data = db.Column(db.Text)
    created_by = db.Column(db.String(100), db.ForeignKey('user.username'), nullable=False)

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
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "User already exists", 400
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        user = User.query.filter_by(username=username, email=email).first()
        if user:
            login_user(user)
            return redirect(url_for('your_diary'))
        return "Invalid credentials", 400
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
        diary_db = Diary(diary_data=write_data, created_by=current_user.username)
        db.session.add(diary_db)
        db.session.commit()
        return redirect(url_for('your_diary'))
    return render_template('create.html')

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

if __name__ == '__main__':
    app.run(debug=True)
