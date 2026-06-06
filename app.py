from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import os
import sqlite3
import logging
from datetime import datetime
import hashlib
import urllib.request
import json as json_module

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'

# Create required directories
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('files', exist_ok=True)

# Setup logging
logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT DEFAULT 'user'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        user TEXT,
        action TEXT,
        ip TEXT,
        details TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'test', 'test123', 'user')")
    conn.commit()
    conn.close()

init_db()

def log_action(user, action, details=""):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs VALUES (NULL, ?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), user, action, request.remote_addr, details))
    conn.commit()
    conn.close()
    logger.info(f"{user} - {action} - {details}")

@app.route('/')
def index():
    return render_template('index.html')

# 1. Login Service
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        log_action(username, 'LOGIN_ATTEMPT', f"username={username}")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # VULNERABLE: SQL Injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            if user:
                session['loggedin'] = True
                session['username'] = user[1]
                session['role'] = user[3]
                log_action(username, 'LOGIN_SUCCESS')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
                log_action(username, 'LOGIN_FAILED', 'Invalid credentials')
        except Exception as e:
            error = 'Database error'
            log_action(username, 'LOGIN_ERROR', str(e))
        conn.close()
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        log_action(username, 'REGISTER_ATTEMPT')
        if not username or not password:
            error = 'All fields required'
        else:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            log_action(username, 'REGISTER_SUCCESS')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    log_action(session.get('username'), 'LOGOUT')
    session.clear()
    return redirect(url_for('index'))

# 2. File Upload Service (VULNERABLE)
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    
    message = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # VULNERABLE: No file type validation
            filename = file.filename
            file.save(os.path.join('uploads', filename))
            log_action(session.get('username'), 'FILE_UPLOAD', f"file={filename}")
            message = f'File {filename} uploaded!'
    return render_template('upload.html', message=message)

# 3. Search / Input Service (VULNERABLE)
@app.route('/search')
def search():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    results = []
    if query:
        log_action(session.get('username'), 'SEARCH', f"query={query}")
        # VULNERABLE: SQL Injection in search
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
            c.execute(sql)
            results = c.fetchall()
        except:
            pass
        conn.close()
    return render_template('search.html', query=query, results=results)

# 4. File Access Service (VULNERABLE)
@app.route('/files/<path:filename>')
def files(filename):
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    
    # VULNERABLE: Path Traversal
    log_action(session.get('username'), 'FILE_ACCESS', f"path={filename}")
    safe_path = os.path.join('files', filename)
    try:
        return send_file(safe_path)
    except:
        return "File not found", 404

# 5. Admin Panel
@app.route('/admin')
def admin():
    if not session.get('loggedin') or session.get('role') != 'admin':
        log_action(session.get('username'), 'UNAUTHORIZED_ADMIN_ACCESS')
        return "Unauthorized", 403
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
    logs = c.fetchall()
    conn.close()
    log_action(session.get('username'), 'ADMIN_ACCESS')
    return render_template('admin.html', users=users, logs=logs)

# Dashboard
@app.route('/dashboard')
def dashboard():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

# 6. API Service (VULNERABLE)
@app.route('/api/users')
def api_users():
    # Vulnerable: No auth check, exposes user data
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()
    return jsonify([{'id': u[0], 'username': u[1], 'role': u[2]} for u in users])

@app.route('/api/fetch')
def api_fetch():
    url = request.args.get('url', '')
    log_action('API', 'FETCH', f"url={url}")
    # VULNERABLE: SSRF
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            content = resp.read().decode('utf-8')[:500]
            return jsonify({'status': 'success', 'content': content})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/logs')
def api_logs():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return jsonify([{'timestamp': l[1], 'user': l[2], 'action': l[3], 'ip': l[4], 'details': l[5]} for l in logs])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)