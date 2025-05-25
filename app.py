from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.schema import UniqueConstraint # Import UniqueConstraint
from sqlalchemy import or_ # Import or_ for complex queries
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import os
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("No FLASK_SECRET_KEY set for Flask application. Please set this environment variable.")
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    username = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(50), unique=True)
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
    is_private = db.Column(db.Boolean, nullable=False, default=False)

class Friendship(db.Model):
    __tablename__ = 'friendship'
    id = db.Column(db.Integer, primary_key=True)
    requestor_id = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    receiver_id = db.Column(db.String(50), db.ForeignKey('user.username'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending') # e.g., pending, accepted, rejected
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (UniqueConstraint('requestor_id', 'receiver_id', name='_requestor_receiver_uc'),)

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
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email address already registered.', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('user sucessfully created', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
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
        # For a checkbox, request.form.get('is_private') will be 'on' if checked, None if not.
        is_private = request.form.get('is_private') == 'on' 
        if not write_data.strip():
            flash('Diary cannot be empty', 'danger')
            return redirect(url_for('create'))
        # Pass the is_private status to the Diary constructor
        diary_db = Diary(diary_data=write_data, created_by=current_user.username, date_created=db.func.now(), is_private=is_private)
        db.session.add(diary_db)
        db.session.commit()
        flash(Markup(f'Diary created successfully! <a href="{url_for("your_diary")}" class="flash-link">View Diary</a>'), 'success')
    return render_template('create.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # This could be a place to list users for friend requests or show general activity
    # For now, it just renders the dashboard with the current user.
    # A list of all users, excluding the current user, could be passed for "add friends" functionality
    all_users = User.query.filter(User.username != current_user.username).all()
    return render_template('dashboard.html', user=current_user, all_users=all_users)


@app.route('/your_diaries')
@login_required
def your_diary():
    # Shows all diaries (public and private) for the currently logged-in user
    diaries = Diary.query.filter_by(created_by=current_user.username).order_by(Diary.date_created.desc()).all()
    return render_template('your_diaries.html', diaries=diaries)

# Route to view a specific diary entry
@app.route('/diary/user/<string:username>/<int:diary_id>')
def diary(username, diary_id): # Removed @login_required to allow viewing public diaries
    diary_entry = Diary.query.filter_by(id=diary_id, created_by=username).first_or_404()

    if diary_entry.is_private:
        # If the diary is private, only the owner can view it
        if not current_user.is_authenticated or current_user.username != diary_entry.created_by:
            flash("This diary is private and can only be viewed by its owner.", "danger")
            return redirect(url_for('index')) # Or redirect to 'user_diaries' for that user
    
    # If diary is public, or if it's private and current_user is the owner
    return render_template('diary.html', diary=diary_entry)

# Route to list diaries for a specific user (publicly or all if owner)
@app.route('/user_diaries/<string:username>')
@login_required 
def user_diaries(username):
    target_user = User.query.filter_by(username=username).first_or_404()
    diaries = []
    if current_user.is_authenticated and current_user.username == username:
        # Owner sees all their diaries
        diaries = Diary.query.filter_by(created_by=username).order_by(Diary.date_created.desc()).all()
    else:
        # Others see only public diaries
        diaries = Diary.query.filter_by(created_by=username, is_private=False).order_by(Diary.date_created.desc()).all()
    
    # The template 'user_diaries_list.html' will need to be created in a frontend task
    return render_template('user_diaries_list.html', diaries=diaries, target_user=target_user)


@app.route("/friends")
@login_required
def friends():
    # Sent friend requests (pending)
    sent_requests_users = db.session.query(User).join(Friendship, User.username == Friendship.receiver_id)\
        .filter(Friendship.requestor_id == current_user.username, Friendship.status == 'pending').all()

    # Received friend requests (pending) - get User objects of requestors
    received_requests_users = db.session.query(User).join(Friendship, User.username == Friendship.requestor_id)\
        .filter(Friendship.receiver_id == current_user.username, Friendship.status == 'pending').all()
    
    # Get actual Friendship objects for received requests to pass their IDs to the template
    received_friendship_objects = Friendship.query.filter_by(receiver_id=current_user.username, status='pending').all()


    # Current friends (accepted)
    current_friends1 = db.session.query(User).join(Friendship, User.username == Friendship.receiver_id)\
        .filter(Friendship.requestor_id == current_user.username, Friendship.status == 'accepted').all()
    current_friends2 = db.session.query(User).join(Friendship, User.username == Friendship.requestor_id)\
        .filter(Friendship.receiver_id == current_user.username, Friendship.status == 'accepted').all()
    current_friend_users = list(set(current_friends1 + current_friends2)) # Combine and remove duplicates

    # Users not yet interacted with (potential friends)
    # Subquery for users current_user has sent requests to or received requests from or is already friends with
    subquery_related_users = db.session.query(Friendship.receiver_id.label("related_user_id"))\
        .filter(Friendship.requestor_id == current_user.username)\
        .union(
            db.session.query(Friendship.requestor_id.label("related_user_id"))\
            .filter(Friendship.receiver_id == current_user.username)
        ).subquery()

    potential_friends = User.query\
        .filter(User.username != current_user.username)\
        .filter(~User.username.in_(db.session.query(subquery_related_users.c.related_user_id))).all()
            
    return render_template('friends.html', 
                           sent_requests_users=sent_requests_users, 
                           received_requests_users=received_requests_users,
                           received_friendship_objects=received_friendship_objects, # Pass these for accept/reject buttons
                           current_friend_users=current_friend_users,
                           potential_friends=potential_friends)


@app.route('/send_friend_request/<string:target_username>', methods=['POST'])
@login_required
def send_friend_request(target_username):
    target_user = User.query.filter_by(username=target_username).first()

    if not target_user:
        flash("User not found.", "danger")
        return redirect(request.referrer or url_for('friends'))

    if target_user.username == current_user.username:
        flash("You cannot send a friend request to yourself.", "danger")
        return redirect(request.referrer or url_for('friends'))

    existing_friendship = Friendship.query.filter(
        or_(
            (Friendship.requestor_id == current_user.username) & (Friendship.receiver_id == target_user.username),
            (Friendship.requestor_id == target_user.username) & (Friendship.receiver_id == current_user.username)
        )
    ).first()

    if existing_friendship:
        if existing_friendship.status == 'pending':
            flash("Friend request already pending.", "warning")
        elif existing_friendship.status == 'accepted':
            flash("You are already friends.", "info")
        return redirect(request.referrer or url_for('friends'))

    new_request = Friendship(requestor_id=current_user.username, receiver_id=target_user.username, status='pending')
    db.session.add(new_request)
    db.session.commit()

    flash(f"Friend request sent to {target_user.username}.", "success")
    return redirect(request.referrer or url_for('friends'))

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    friend_request = Friendship.query.get(request_id)
    if not friend_request:
        flash("Friend request not found.", "danger")
        return redirect(url_for('friends'))
    
    if friend_request.receiver_id != current_user.username:
        flash("You are not authorized to accept this request.", "danger")
        return redirect(url_for('friends'))

    if friend_request.status != 'pending':
        flash("This friend request is no longer pending.", "warning")
        return redirect(url_for('friends'))

    friend_request.status = 'accepted'
    db.session.commit()
    flash(f"Friend request from {friend_request.requestor_id} accepted.", "success")
    return redirect(url_for('friends'))

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    friend_request = Friendship.query.get(request_id)
    if not friend_request:
        flash("Friend request not found.", "danger")
        return redirect(url_for('friends'))

    if friend_request.receiver_id != current_user.username:
        flash("You are not authorized to reject this request.", "danger")
        return redirect(url_for('friends'))

    if friend_request.status != 'pending':
        flash("This friend request is no longer pending.", "warning")
        return redirect(url_for('friends'))

    db.session.delete(friend_request)
    db.session.commit()
    flash(f"Friend request from {friend_request.requestor_id} rejected.", "success")
    return redirect(url_for('friends'))

@app.route('/remove_friend/<string:friend_username>', methods=['POST'])
@login_required
def remove_friend(friend_username):
    friend_user = User.query.filter_by(username=friend_username).first()
    if not friend_user:
        flash(f"User {friend_username} not found.", "danger")
        return redirect(url_for('friends'))

    friendship_to_remove = Friendship.query.filter(
        or_(
            (Friendship.requestor_id == current_user.username) & (Friendship.receiver_id == friend_user.username),
            (Friendship.requestor_id == friend_user.username) & (Friendship.receiver_id == current_user.username)
        ),
        Friendship.status == 'accepted'
    ).first()

    if not friendship_to_remove:
        flash(f"You are not friends with {friend_username}.", "warning")
        return redirect(url_for('friends'))

    db.session.delete(friendship_to_remove)
    db.session.commit()
    flash(f"{friend_username} has been removed from your friends.", "success")
    return redirect(url_for('friends'))

if __name__ == '__main__':
    app.run(debug=True)
