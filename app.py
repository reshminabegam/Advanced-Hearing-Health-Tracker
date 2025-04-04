from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import re
from functools import wraps

app = Flask(__name__)
app.secret_key = "e9054de4604b04b4344cb4f8ada09728d349165ede412f8a60724ff2874bf3b9"
app.permanent_session_lifetime = timedelta(minutes=30)

# Database Initialization and Migration
def init_db():
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            email TEXT
                        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS test_results (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            test_date TEXT,
                            ear TEXT,
                            frequency INTEGER,
                            heard BOOLEAN,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Input validation
def is_valid_username(username):
    return re.match("^[a-zA-Z0-9_]{3,20}$", username) is not None

def is_valid_password(password):
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

@app.route('/')
def home():
    return render_template("i-1.html", logged_in='username' in session)

@app.route('/check-auth')
def check_auth():
    return jsonify({
        'authenticated': 'username' in session,
        'username': session.get('username', '')
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '')
        
        if not is_valid_username(username):
            flash("Username must be 3-20 characters, letters, numbers, and underscores only", "danger")
            return render_template("register.html")
        if not is_valid_password(password):
            flash("Password must be at least 8 characters with uppercase and numbers", "danger")
            return render_template("register.html")
        if email and not is_valid_email(email):
            flash("Invalid email format", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if email:
                cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
                if cursor.fetchone()[0] > 0:
                    flash("Email already exists.", "danger")
                    return render_template("register.html")
            
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                         (username, hashed_password, email if email else None))
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['username']  # Can be username or email
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user["password"], password):
            session.permanent = remember
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['logged_in'] = True
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username/email or password.", "danger")
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    response = make_response(redirect(url_for('home')))
    response.set_cookie('session', '', expires=0)
    response.set_cookie('remember_token', '', expires=0)
    return response

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully"}), 200

@app.route('/instructions')
def instructions():
    return render_template("instructions.html")

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch user details including email
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # Fetch test results
    cursor.execute("SELECT * FROM test_results WHERE user_id = ? ORDER BY test_date DESC LIMIT 2", 
                  (session['user_id'],))
    results = cursor.fetchall()
    conn.close()
    
    # Use email if available, otherwise fallback to username
    display_name = user['email'] if user['email'] else user['username']
    
    return render_template("dashboard.html", 
                         username=display_name,
                         results=results)

@app.route('/index', methods=['GET', 'POST'])
@login_required
def hearing_test():
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
            ear = data['ear']
            frequency = int(data['frequency'])
            heard = data['heard']
            
            print(f"Saving test result - User: {session['user_id']}, Ear: {ear}, Freq: {frequency}, Heard: {heard}")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO test_results (user_id, test_date, ear, frequency, heard)
                VALUES (?, ?, ?, ?, ?)
            """, (session['user_id'], datetime.now().isoformat(), ear, frequency, heard))
            conn.commit()
            conn.close()
            
            print("Test result saved successfully")
            return jsonify({"status": "success"})
        except KeyError as e:
            print(f"Missing field: {e}")
            return jsonify({"status": "error", "message": f"Missing field: {e}"}), 400
        except ValueError as e:
            print(f"Value error: {e}")
            return jsonify({"status": "error", "message": "Invalid frequency value"}), 400
        except Exception as e:
            print(f"Error saving test result: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    return render_template("index.html")

@app.route('/chart')
@login_required
def chart():
    conn = get_db_connection()
    cursor = conn.cursor()
    print(f"Querying test_results for user_id: {session['user_id']}")
    cursor.execute("SELECT * FROM test_results WHERE user_id = ? ORDER BY test_date DESC", 
                  (session['user_id'],))
    results = cursor.fetchall()
    print(f"Found {len(results)} results: {[dict(row) for row in results]}")
    conn.close()
    
    return render_template("chart.html", results=results)

@app.route('/location')
def location():
    return render_template("location.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)