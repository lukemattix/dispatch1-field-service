from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

USERS = {"admin": "password123"}
JOBS = []

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
    return render_template('dashboard.html', jobs=JOBS)

@app.route('/add-job', methods=['GET', 'POST'])
@login_required
def add_job():
    if request.method == 'POST':
        JOBS.append({
            'site': request.form['site'],
            'date': request.form['date'],
            'tech': request.form['tech'],
            'status': request.form['status']
        })
        return redirect(url_for('dashboard'))
    return render_template('add_job.html')

if __name__ == '__main__':
    print("Flask app is starting...")
    app.run(debug=True, host="0.0.0.0", port=5050)