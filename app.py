from flask import Flask, render_template, redirect, url_for, request, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, \
    logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import os
from datetime import datetime
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


def generate_ticket_number():
    """Generate a unique ticket number in format TK-YYYYMMDD-XXXX"""
    today = datetime.now().strftime('%Y%m%d')
    prefix = f"TK-{today}-"
    last_ticket = Job.query.filter(Job.ticket_number.like(f"{prefix}%")).order_by(Job.ticket_number.desc()).first()
    
    if last_ticket:
        last_num = int(last_ticket.ticket_number.split('-')[-1])
        new_num = last_num + 1
    else:
        new_num = 1
    
    return f"{prefix}{new_num:04d}"


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


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    organization = db.Column(db.String(120))
    end_clients = db.relationship('EndClient', backref='client', lazy=True)
    contracts = db.relationship('Contract', backref='client', lazy=True)
    jobs = db.relationship('Job', backref='client', lazy=True)


class EndClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(200))
    city = db.Column(db.String(80))
    state = db.Column(db.String(20))
    zip_code = db.Column(db.String(10))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    jobs = db.relationship('Job', backref='end_client', lazy=True)


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_name = db.Column(db.String(120), nullable=False)
    terms = db.Column(db.Text)
    date = db.Column(db.String(50))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    jobs = db.relationship('Job', backref='contract', lazy=True)


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True, nullable=False)
    site = db.Column(db.String(120))
    date = db.Column(db.String(50))
    tech = db.Column(db.String(80))
    status = db.Column(db.String(50))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
    end_client_id = db.Column(db.Integer, db.ForeignKey('end_client.id'))
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'))


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


def build_job_query():
    """Build a job query with common filtering logic based on user role and request parameters."""
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
    
    return query


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
    jobs = build_job_query().all()
    return render_template('dashboard.html', jobs=jobs)


@app.route('/add-job', methods=['GET', 'POST'])
@login_required
def add_job():
    if request.method == 'POST':
        client_id = None
        end_client_id = None
        contract_id = None
        
        if request.form.get('client_action') == 'new':
            client = Client(
                name=request.form['client_name'],
                email=request.form.get('client_email'),
                phone=request.form.get('client_phone'),
                organization=request.form.get('client_organization')
            )
            db.session.add(client)
            db.session.flush()
            client_id = client.id
        elif request.form.get('existing_client'):
            client_id = int(request.form['existing_client'])
        
        if request.form.get('site_action') == 'new':
            end_client = EndClient(
                site_name=request.form['site_name'],
                address=request.form.get('site_address'),
                city=request.form.get('site_city'),
                state=request.form.get('site_state'),
                zip_code=request.form.get('site_zip'),
                client_id=client_id
            )
            db.session.add(end_client)
            db.session.flush()
            end_client_id = end_client.id
        elif request.form.get('existing_site'):
            end_client_id = int(request.form['existing_site'])
        
        if request.form.get('existing_contract'):
            contract_id = int(request.form['existing_contract'])
        
        job = Job(
            ticket_number=generate_ticket_number(),
            site=request.form.get('site_name') or request.form.get('site'),
            date=request.form['date'],
            tech=request.form['tech'],
            status=request.form['status'],
            client_id=client_id,
            end_client_id=end_client_id,
            contract_id=contract_id
        )
        db.session.add(job)
        db.session.commit()
        tech_user = User.query.filter_by(username=job.tech).first()
        if tech_user and tech_user.email:
            send_email(tech_user.email, 'New Job Assigned', f'Job {job.ticket_number} at {job.site} on {job.date} created. Status: {job.status}.')
        return redirect(url_for('dashboard'))
    
    clients = Client.query.all()
    end_clients = EndClient.query.all()
    contracts = Contract.query.all()
    return render_template('add_job.html', clients=clients, end_clients=end_clients, contracts=contracts)


@app.route('/edit-job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Job.query.get_or_404(job_id)
    if request.method == 'POST':
        job.site = request.form['site']
        job.date = request.form['date']
        job.tech = request.form['tech']
        job.status = request.form['status']
        
        if request.form.get('existing_client'):
            job.client_id = int(request.form['existing_client'])
        if request.form.get('existing_site'):
            job.end_client_id = int(request.form['existing_site'])
        if request.form.get('existing_contract'):
            job.contract_id = int(request.form['existing_contract']) if request.form['existing_contract'] else None
        
        db.session.commit()
        tech_user = User.query.filter_by(username=job.tech).first()
        if tech_user and tech_user.email:
            send_email(tech_user.email, 'Job Updated', f'Job {job.ticket_number} at {job.site} on {job.date} updated. Status: {job.status}.')
        return redirect(url_for('dashboard'))
    
    clients = Client.query.all()
    end_clients = EndClient.query.all()
    contracts = Contract.query.all()
    return render_template('edit_job.html', job=job, clients=clients, end_clients=end_clients, contracts=contracts)


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
    jobs = build_job_query().all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ticket_number', 'id', 'site', 'date', 'tech', 'status', 'client', 'end_client', 'contract'])
    for j in jobs:
        client_name = j.client.name if j.client else ''
        end_client_name = j.end_client.site_name if j.end_client else ''
        contract_name = j.contract.contract_name if j.contract else ''
        cw.writerow([j.ticket_number, j.id, j.site, j.date, j.tech, j.status, client_name, end_client_name, contract_name])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=jobs.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/contracts')
@login_required
def contracts():
    contracts = Contract.query.all()
    return render_template('contracts.html', contracts=contracts)


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
