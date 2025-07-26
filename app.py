from flask import Flask, render_template, redirect, url_for, request, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, \
    logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SENDGRID_API_KEY'] = os.environ.get('SENDGRID_API_KEY')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def send_email(to_email: str, subject: str, content: str) -> None:
    api_key = app.config.get('SENDGRID_API_KEY') or os.environ.get('SENDGRID_API_KEY')
    if not api_key or not to_email:
        return
    message = Mail(from_email='no-reply@example.com', to_emails=to_email,
                    subject=subject, plain_text_content=content)
    try:
        sg = SendGridAPIClient(api_key)
        sg.send(message)
    except Exception:
        pass


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='tech')
    email = db.Column(db.String(120))

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
    query = Job.query
    if current_user.role == 'tech':
        query = query.filter_by(tech=current_user.username)
    status = request.args.get('status')
    start = request.args.get('start')
    end = request.args.get('end')
    if status:
        query = query.filter_by(status=status)
    if start:
        query = query.filter(Job.date >= start)
    if end:
        query = query.filter(Job.date <= end)
    jobs = query.all()
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
        tech_user = User.query.filter_by(username=job.tech).first()
        if tech_user and tech_user.email:
            send_email(tech_user.email, 'New Job Assigned', f'Job at {job.site} on {job.date} created. Status: {job.status}.')
        return redirect(url_for('dashboard'))
    return render_template('add_job.html')


@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        job.site = request.form['site']
        job.date = request.form['date']
        job.tech = request.form['tech']
        job.status = request.form['status']
        db.session.commit()
        tech_user = User.query.filter_by(username=job.tech).first()
        if tech_user and tech_user.email:
            send_email(tech_user.email, 'Job Updated', f'Job at {job.site} on {job.date} updated. Status: {job.status}.')
        return redirect(url_for('dashboard'))
    return render_template('edit_job.html', job=job)


@app.route('/delete-job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    job = Job.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/update-job-status/<int:job_id>', methods=['POST'])
@login_required
def update_job_status(job_id):
    job = Job.query.get_or_404(job_id)
    new_status = request.get_json().get('status')
    job.status = new_status
    db.session.commit()
    tech_user = User.query.filter_by(username=job.tech).first()
    if tech_user and tech_user.email:
        send_email(tech_user.email, 'Job Status Updated', f'Status for job at {job.site} on {job.date} changed to {job.status}.')
    return {'status': job.status}


@app.route('/download-csv')
@login_required
def download_csv():
    query = Job.query
    if current_user.role == 'tech':
        query = query.filter_by(tech=current_user.username)
    status = request.args.get('status')
    start = request.args.get('start')
    end = request.args.get('end')
    if status:
        query = query.filter_by(status=status)
    if start:
        query = query.filter(Job.date >= start)
    if end:
        query = query.filter(Job.date <= end)
    jobs = query.all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['id', 'site', 'date', 'tech', 'status'])
    for j in jobs:
        cw.writerow([j.id, j.site, j.date, j.tech, j.status])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=jobs.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role != 'admin':
        flash('Admin access required.')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email')
        role = request.form.get('role', 'tech') or 'tech'
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
        else:
            user = User(username=username, role=role, email=email)
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
            admin = User(username='admin', role='admin', email='admin@example.com')
            admin.set_password('password123')
            db.session.add(admin)
            db.session.commit()
    print('Flask app is starting...')
    app.run(debug=True, host='0.0.0.0', port=5050)
