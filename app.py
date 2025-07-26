from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, \
    logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='tech')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120))
    date = db.Column(db.String(50))
    tech = db.Column(db.String(80))
    status = db.Column(db.String(50))


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Wrong credentials')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'tech':
        jobs = Job.query.filter_by(tech=current_user.username).all()
    else:
        jobs = Job.query.all()
    return render_template('dashboard.html', jobs=jobs)


@app.route('/add-job', methods=['GET', 'POST'])
@login_required
def add_job():
    if request.method == 'POST':
        job = Job(
            site=request.form['site'],
            date=request.form['date'],
            tech=request.form['tech'],
            status=request.form['status'],
        )
        db.session.add(job)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_job.html')


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'admin':
        flash('Admin access required.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'tech') or 'tech'
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
        else:
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('User registered.')
            return redirect(url_for('dashboard'))
    return render_template('register.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('password123')
            db.session.add(admin)
            db.session.commit()
    print('Flask app is starting...')
    app.run(debug=True, host='0.0.0.0', port=5050)
