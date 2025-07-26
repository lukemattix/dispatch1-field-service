from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False)
    date = db.Column(db.Date, nullable=False)
    tech = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(80), nullable=False)

with app.app_context():
    db.create_all()

USERS = {"admin": "password123"}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash("Login required.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        if USERS.get(u) == p:
            session['username'] = u
            return redirect(url_for('dashboard'))
        flash("Wrong credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    jobs = Job.query.all()
    return render_template('dashboard.html', jobs=jobs)

@app.route('/add-job', methods=['GET', 'POST'])
@login_required
def add_job():
    if request.method == 'POST':
        job = Job(
            site=request.form['site'],
            date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
            tech=request.form['tech'],
            status=request.form['status']
        )
        db.session.add(job)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_job.html')

if __name__ == '__main__':
    print("Flask app is starting...")
    app.run(debug=True, host="0.0.0.0", port=5050)