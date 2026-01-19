from flask import Flask, render_template, redirect, url_for, request, flash, Response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import csv
import io
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dream-earning-secret'
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    points = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    tasks_completed = db.Column(db.Integer, default=0)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reward = db.Column(db.Integer, nullable=False)
    link = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    task_type = db.Column(db.String(50), default='download')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    screenshot = db.Column(db.String(255), nullable=False)
    note = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    user = db.relationship('User', backref='submissions')
    task = db.relationship('Task', backref='submissions')

class Payout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    method = db.Column(db.String(50), nullable=False)
    account = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    date_requested = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='payouts')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not username or not password:
            flash('Please fill all fields')
            return redirect(url_for('signup'))
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        if len(password) < 4:
            flash('Password must be at least 4 characters')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Account created successfully!')
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if user.is_banned:
                flash('Your account has been banned.')
                return redirect(url_for('login'))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(is_active=True).all()
    submissions = Submission.query.filter_by(user_id=current_user.id).order_by(Submission.submitted_at.desc()).limit(5).all()
    pending_count = Submission.query.filter_by(user_id=current_user.id, status='pending').count()
    approved_count = Submission.query.filter_by(user_id=current_user.id, status='approved').count()
    return render_template('dashboard.html', tasks=tasks, submissions=submissions, pending_count=pending_count, approved_count=approved_count)

@app.route('/tasks')
@login_required
def tasks_page():
    tasks = Task.query.filter_by(is_active=True).all()
    return render_template('tasks.html', tasks=tasks)

@app.route('/submit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def submit_task(task_id):
    task = Task.query.get_or_404(task_id)
    existing = Submission.query.filter_by(user_id=current_user.id, task_id=task_id, status='pending').first()
    if existing:
        flash('You already have a pending submission for this task')
        return redirect(url_for('history'))
    if request.method == 'POST':
        if 'screenshot' not in request.files:
            flash('No screenshot uploaded')
            return redirect(request.url)
        file = request.files['screenshot']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            note = request.form.get('note', '')
            submission = Submission(
                user_id=current_user.id,
                task_id=task_id,
                screenshot=filename,
                note=note
            )
            db.session.add(submission)
            db.session.commit()
            flash('Task submitted successfully! Wait for admin approval.')
            return redirect(url_for('history'))
        else:
            flash('Invalid file type. Use PNG, JPG, or GIF')
    return render_template('submit.html', task=task)

@app.route('/history')
@login_required
def history():
    submissions = Submission.query.filter_by(user_id=current_user.id).order_by(Submission.submitted_at.desc()).all()
    return render_template('history.html', submissions=submissions)

@app.route('/payout', methods=['POST'])
@login_required
def payout():
    method = request.form.get('method')
    account = request.form.get('account')
    amount_str = request.form.get('amount')
    try:
        amount = int(amount_str)
    except (ValueError, TypeError):
        flash('Invalid amount')
        return redirect(url_for('dashboard'))
    if amount < 100:
        flash('Minimum withdrawal is 100 points')
        return redirect(url_for('dashboard'))
    if current_user.points >= amount:
        new_payout = Payout(user_id=current_user.id, method=method, account=account, amount=amount)
        current_user.points -= amount
        db.session.add(new_payout)
        db.session.commit()
        flash('Payout request submitted!')
    else:
        flash('Insufficient points')
    return redirect(url_for('dashboard'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    total_users = User.query.filter_by(is_admin=False).count()
    total_points = db.session.query(db.func.sum(User.points)).scalar() or 0
    total_tasks = Task.query.filter_by(is_active=True).count()
    pending_submissions = Submission.query.filter_by(status='pending').count()
    pending_payouts = Payout.query.filter_by(status='pending').count()
    approved_payouts = Payout.query.filter_by(status='approved').count()
    total_payout_amount = db.session.query(db.func.sum(Payout.amount)).filter(Payout.status.in_(['approved', 'paid'])).scalar() or 0
    recent_submissions = Submission.query.filter_by(status='pending').order_by(Submission.submitted_at.desc()).limit(5).all()
    return render_template('admin/dashboard.html', 
        total_users=total_users,
        total_points=total_points,
        total_tasks=total_tasks,
        pending_submissions=pending_submissions,
        pending_payouts=pending_payouts,
        approved_payouts=approved_payouts,
        total_payout_amount=total_payout_amount,
        recent_submissions=recent_submissions
    )

@app.route('/admin/submissions')
@login_required
def admin_submissions():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    status_filter = request.args.get('status', 'pending')
    if status_filter == 'all':
        submissions = Submission.query.order_by(Submission.submitted_at.desc()).all()
    else:
        submissions = Submission.query.filter_by(status=status_filter).order_by(Submission.submitted_at.desc()).all()
    return render_template('admin/submissions.html', submissions=submissions, current_filter=status_filter)

@app.route('/admin/submissions/<int:sub_id>/approve', methods=['POST'])
@login_required
def admin_approve_submission(sub_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    submission = Submission.query.get_or_404(sub_id)
    if submission.status == 'pending':
        submission.status = 'approved'
        submission.reviewed_at = datetime.utcnow()
        user = User.query.get(submission.user_id)
        if user:
            user.points += submission.task.reward
            user.tasks_completed += 1
        db.session.commit()
        flash(f'Submission approved! {submission.task.reward} points added.')
    return redirect(url_for('admin_submissions'))

@app.route('/admin/submissions/<int:sub_id>/reject', methods=['POST'])
@login_required
def admin_reject_submission(sub_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    submission = Submission.query.get_or_404(sub_id)
    if submission.status == 'pending':
        submission.status = 'rejected'
        submission.reviewed_at = datetime.utcnow()
        db.session.commit()
        flash('Submission rejected.')
    return redirect(url_for('admin_submissions'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    users = User.query.filter_by(is_admin=False).order_by(User.date_joined.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.points = int(request.form.get('points', 0))
        db.session.commit()
        flash(f'User {user.username} updated!')
        return redirect(url_for('admin_users'))
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/<int:user_id>/ban', methods=['POST'])
@login_required
def admin_ban_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.is_banned = not user.is_banned
    db.session.commit()
    status = 'banned' if user.is_banned else 'unbanned'
    flash(f'User {user.username} has been {status}!')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    Submission.query.filter_by(user_id=user_id).delete()
    Payout.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted!')
    return redirect(url_for('admin_users'))

@app.route('/admin/tasks')
@login_required
def admin_tasks():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    tasks = Task.query.order_by(Task.created_at.desc()).all()
    return render_template('admin/tasks.html', tasks=tasks)

@app.route('/admin/tasks/add', methods=['GET', 'POST'])
@login_required
def admin_add_task():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        task = Task(
            title=request.form.get('title'),
            description=request.form.get('description'),
            reward=int(request.form.get('reward')),
            link=request.form.get('link'),
            task_type=request.form.get('task_type', 'download'),
            is_active=request.form.get('is_active') == 'on'
        )
        db.session.add(task)
        db.session.commit()
        flash('Task added successfully!')
        return redirect(url_for('admin_tasks'))
    return render_template('admin/add_task.html')

@app.route('/admin/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_task(task_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        task.title = request.form.get('title')
        task.description = request.form.get('description')
        task.reward = int(request.form.get('reward'))
        task.link = request.form.get('link')
        task.task_type = request.form.get('task_type', 'download')
        task.is_active = request.form.get('is_active') == 'on'
        db.session.commit()
        flash('Task updated!')
        return redirect(url_for('admin_tasks'))
    return render_template('admin/edit_task.html', task=task)

@app.route('/admin/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_task(task_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    task = Task.query.get_or_404(task_id)
    task.is_active = not task.is_active
    db.session.commit()
    status = 'activated' if task.is_active else 'deactivated'
    flash(f'Task {status}!')
    return redirect(url_for('admin_tasks'))

@app.route('/admin/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def admin_delete_task(task_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    task = Task.query.get_or_404(task_id)
    Submission.query.filter_by(task_id=task_id).delete()
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted!')
    return redirect(url_for('admin_tasks'))

@app.route('/admin/payouts')
@login_required
def admin_payouts():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    status_filter = request.args.get('status', 'all')
    if status_filter == 'all':
        payouts = Payout.query.order_by(Payout.date_requested.desc()).all()
    else:
        payouts = Payout.query.filter_by(status=status_filter).order_by(Payout.date_requested.desc()).all()
    return render_template('admin/payouts.html', payouts=payouts, current_filter=status_filter)

@app.route('/admin/payouts/<int:payout_id>/approve', methods=['POST'])
@login_required
def admin_approve_payout(payout_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    payout = Payout.query.get_or_404(payout_id)
    payout.status = 'approved'
    db.session.commit()
    flash(f'Payout #{payout_id} approved!')
    return redirect(url_for('admin_payouts'))

@app.route('/admin/payouts/<int:payout_id>/decline', methods=['POST'])
@login_required
def admin_decline_payout(payout_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    payout = Payout.query.get_or_404(payout_id)
    user = User.query.get(payout.user_id)
    if user:
        user.points += payout.amount
    payout.status = 'declined'
    db.session.commit()
    flash(f'Payout #{payout_id} declined. Points refunded.')
    return redirect(url_for('admin_payouts'))

@app.route('/admin/payouts/<int:payout_id>/paid', methods=['POST'])
@login_required
def admin_mark_paid(payout_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    payout = Payout.query.get_or_404(payout_id)
    payout.status = 'paid'
    db.session.commit()
    flash(f'Payout #{payout_id} marked as paid!')
    return redirect(url_for('admin_payouts'))

@app.route('/admin/payouts/export')
@login_required
def admin_export_payouts():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    payouts = Payout.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Method', 'Account', 'Amount', 'Status', 'Date Requested'])
    for p in payouts:
        user = User.query.get(p.user_id)
        writer.writerow([p.id, user.username if user else 'Unknown', p.method, p.account, p.amount, p.status, p.date_requested])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=payouts.csv'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            admin_user.is_admin = True
            db.session.commit()
        else:
            admin_user = User(
                username='admin', 
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
        if not Task.query.first():
            tasks = [
                Task(title="Download Dream App", description="Install our official app and open it for 30 seconds. Take a screenshot showing the app is installed.", reward=50, link="https://example.com/app", task_type="download"),
                Task(title="Complete Survey", description="Complete the short survey about your mobile usage. Screenshot the completion page.", reward=30, link="https://example.com/survey", task_type="survey"),
                Task(title="Watch Video Ad", description="Watch the full promotional video (2 minutes). Screenshot at the end.", reward=20, link="https://example.com/video", task_type="watch")
            ]
            for t in tasks:
                db.session.add(t)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000)
