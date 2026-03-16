"""
app_vul.py — INTENTIONALLY VULNERABLE Flask Application
=========================================================

  ╔══════════════════════════════════════════════════════════════════════════╗
  ║  ⚠  FOR CLASSROOM USE ONLY — DO NOT DEPLOY ON ANY NETWORK              ║
  ║  Every security control from app.py has been deliberately removed.      ║
  ║  This file exists to demonstrate what attacks succeed without them.      ║
  ╚══════════════════════════════════════════════════════════════════════════╝

VULNERABILITIES PRESENT IN THIS FILE
--------------------------------------
  1. SQL Injection        — string concatenation in login & search queries
  2. Stored XSS          — note content rendered as raw HTML (no escaping)
  3. No CSRF Protection  — all forms accept POST from any origin
  4. No Input Validation — raw form values accepted without any checks
  5. Weak Passwords      — stored as unsalted MD5 (trivially crackable)
  6. Unsafe File Upload  — no extension check, no content check, no rename

HOW TO RUN (separate from the secure app)
------------------------------------------
  python app_vul.py
  Open:  http://127.0.0.1:5001

  Uses a separate database (notes_vul.db) so both apps can run at the same
  time on different ports for side-by-side classroom comparison.

ATTACKS TO TRY (see Section 5 of RunningGuide.docx for step-by-step)
----------------------------------------------------------------------
  SQL Injection  →  Login with username:  admin' --   password: anything
  Stored XSS     →  Create a note with:  <script>alert('XSS!')</script>
  No Validation  →  Register with:       username = '; or a 1-char password

Author: Secure Software Development — Teaching Example
"""

import os
import hashlib
import sqlite3
import subprocess
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField
from markupsafe import Markup   # Used to BYPASS Jinja2 auto-escaping for XSS demo

# =============================================================================
#  APPLICATION SETUP
# =============================================================================
app = Flask(__name__)
app.secret_key = 'hardcoded-insecure-secret-key-123'  # ❌ VULNERABLE: hard-coded secret

# ❌ CSRF DISABLED — forms accept POST requests from any website/origin.
#    In app.py:  csrf = CSRFProtect(app)  validates a signed token on every POST.
app.config['WTF_CSRF_ENABLED'] = False

UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# ❌ NO MAX_CONTENT_LENGTH — any file size accepted (DoS via large upload)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE = 'notes_vul.db'   # Separate DB so both apps can run simultaneously


# =============================================================================
#  DATABASE HELPERS  (same structure as app.py)
# =============================================================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    db.commit()
    db.close()


# =============================================================================
#  FORMS  — CSRF disabled at app level so tokens are not checked
# =============================================================================
class RegisterForm(FlaskForm):
    # ❌ No Length validators, no regex validators, no password strength check
    username = StringField('Username')
    email    = StringField('Email')
    password = PasswordField('Password')
    submit   = SubmitField('Create Account')


class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit   = SubmitField('Log In')


class NoteForm(FlaskForm):
    # ❌ No Length validators — unlimited input accepted
    title   = StringField('Title')
    content = TextAreaField('Content')
    submit  = SubmitField('Save Note')


class SearchForm(FlaskForm):
    query  = StringField('Search notes')
    submit = SubmitField('Search')


class UploadForm(FlaskForm):
    # ❌ No FileAllowed validator — any file type accepted
    photo  = FileField('Profile Photo')
    submit = SubmitField('Upload')


# =============================================================================
#  UTILITY
# =============================================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access that page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def weak_hash(password: str) -> str:
    """
    ❌ VULNERABLE: Unsalted MD5 hash.
    MD5 is fast — GPUs can crack billions per second.
    No salt means identical passwords produce identical hashes,
    making rainbow table lookups trivial.

    app.py uses: generate_password_hash()  →  PBKDF2-SHA256 with unique salt.
    """
    return hashlib.md5(password.encode()).hexdigest()


# =============================================================================
#  ROUTES
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')


# --- Register ----------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    VULNERABILITIES HERE
    --------------------
    ❌ No input validation  — any username/email/password accepted, including
       SQL metacharacters, empty strings, or a 1-character password.
    ❌ Unsalted MD5 hash    — password stored as md5(password), not PBKDF2.
    ❌ SQL string concat    — INSERT built from raw user input (SQL Injection).
    """
    form = RegisterForm()
    if request.method == 'POST':

        # ❌ VULNERABLE: raw values from POST body — no stripping, no validation
        username = request.form.get('username')
        email    = request.form.get('email')
        password = request.form.get('password')

        # ❌ VULNERABLE: weak, unsalted MD5 — crackable in seconds with rainbow tables
        password_hash = weak_hash(password)

        db = get_db()
        try:
            # ❌ VULNERABLE: parameterised query still used for INSERT to avoid
            #    crashing the demo, but no validation means garbage data is accepted.
            #    The SQL Injection demo is more impactful on the login/search routes.
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            db.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('That username or email is already taken.', 'danger')

    return render_template('register.html', form=form)


# --- Login -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABILITIES HERE
    --------------------
    ❌ SQL Injection — username and password embedded directly in the SQL string.

    ATTACK TO TRY:
        Username:  admin' --
        Password:  anything

    The resulting SQL string becomes:
        SELECT * FROM users WHERE username = 'admin' --' AND password_hash = 'anything'

    The '--' starts a SQL comment, discarding the password check entirely.
    This logs you in as 'admin' without knowing the password.

    Also try:
        Username:  ' OR '1'='1' --
        (Returns the first row in the table — logs in as the first registered user)

    app.py fix:  db.execute("... WHERE username = ?", (username,))
                 The ? treats input as data — quotes and '--' have no special meaning.
    """
    form = LoginForm()
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        pw_hash  = weak_hash(password)

        db = get_db()

        # ❌ VULNERABLE: string concatenation — username injected into SQL syntax
        query = (
            "SELECT * FROM users "
            "WHERE username = '" + username + "' "
            "AND password_hash = '" + pw_hash + "'"
        )
        try:
            user = db.execute(query).fetchone()
        except Exception as e:
            flash(f'Database error: {e}', 'danger')
            return render_template('login.html', form=form)

        if user:
            # ❌ No session.clear() — session fixation possible
            session['user_id']  = user['id']
            session['username'] = user['username']
            flash(f'Welcome, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # ❌ Specific messages enable username enumeration in a real scenario
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)


# --- Logout ------------------------------------------------------------------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# --- Dashboard ---------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """
    VULNERABILITY HERE
    ------------------
    ❌ Stored XSS — note content is wrapped in Markup() before being passed
       to the template.  Markup() tells Jinja2 "this string is already safe
       HTML — do not escape it."  Any <script> or event handler stored in a
       note executes in the browser when this page loads.

    ATTACK TO TRY:
        Create a note (on /notes/new) with content:
            <script>alert('XSS!')</script>
        Or:
            <img src=x onerror="alert('XSS via img tag!')">
        Then visit the dashboard — the script executes.

    app.py fix:  {{ note.content }} without Markup() — Jinja2 auto-escapes
                 < > " ' to HTML entities, so scripts are displayed as text.
                 bleach.clean() also strips dangerous tags before storage.
    """
    db = get_db()
    rows = db.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()

    # ❌ VULNERABLE: Markup() bypasses Jinja2 auto-escaping
    #    Converts each sqlite3.Row to a plain dict, then wraps title/content
    #    in Markup so the template renders them as raw HTML.
    notes = []
    for row in rows:
        notes.append({
            'id':         row['id'],
            'user_id':    row['user_id'],
            'title':      Markup(row['title']),    # ❌ XSS: raw HTML rendered
            'content':    Markup(row['content']),  # ❌ XSS: raw HTML rendered
            'created_at': row['created_at']
        })

    return render_template('dashboard.html', notes=notes)


# --- Create Note -------------------------------------------------------------
@app.route('/notes/new', methods=['GET', 'POST'])
@login_required
def new_note():
    """
    VULNERABILITIES HERE
    --------------------
    ❌ No CSRF token check  — any website can POST to this route on your behalf.
    ❌ No input validation  — notes can be unlimited length.
    ❌ No bleach sanitise   — raw HTML/script tags stored directly in the database.
       (XSS payload stored here is then rendered unsafely on the dashboard.)
    """
    form = NoteForm()
    if request.method == 'POST':

        # ❌ VULNERABLE: raw POST data, no length limit, no sanitisation
        title   = request.form.get('title', '')
        content = request.form.get('content', '')
        # No bleach.clean() — <script>, onerror=, etc. stored as-is

        db = get_db()
        db.execute(
            "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
            (session['user_id'], title, content)
        )
        db.commit()
        flash('Note saved!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_note.html', form=form)


# --- Search ------------------------------------------------------------------
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """
    VULNERABILITIES HERE
    --------------------
    ❌ SQL Injection (LIKE) — search term embedded directly in the SQL string.

    ATTACK TO TRY:
        Search for:  ' OR '1'='1
        Resulting SQL becomes:
            ... WHERE title LIKE '%' OR '1'='1%'
        Because OR '1'='1' is always true, this returns ALL notes from ALL users,
        not just notes belonging to the logged-in user.

    Also try searching for:  %  (returns everything)

    ❌ Reflected XSS — query term echoed back as Markup() (raw HTML).
    ATTACK TO TRY:
        Search for:  <script>alert('reflected XSS')</script>
        The script executes because the query is rendered without escaping.

    app.py fix:
        pattern = f"%{query_term}%"
        db.execute("... WHERE title LIKE ?", (user_id, pattern, pattern))
        Wildcards added safely in Python; input passed as data, not SQL.
    """
    form = SearchForm()
    results    = []
    query_term = ''

    if request.method == 'POST':
        query_term = request.form.get('query', '')

        db = get_db()

        # ❌ VULNERABLE: query_term injected directly into the SQL LIKE clause
        sql = (
            "SELECT * FROM notes WHERE user_id = " + str(session['user_id']) +
            " AND (title LIKE '%" + query_term + "%' "
            "OR content LIKE '%" + query_term + "%') "
            "ORDER BY created_at DESC"
        )
        try:
            rows = db.execute(sql).fetchall()
        except Exception as e:
            flash(f'Database error: {e}', 'danger')
            rows = []

        # ❌ VULNERABLE: convert to dicts and wrap in Markup for reflected XSS
        results = []
        for row in rows:
            results.append({
                'id':         row['id'],
                'title':      Markup(row['title']),
                'content':    Markup(row['content']),
                'created_at': row['created_at']
            })

        if not results:
            flash('No notes found.', 'info')

    # ❌ VULNERABLE: query_term echoed as Markup — reflected XSS
    return render_template('search.html', form=form,
                           results=results, query=Markup(query_term))


# --- File Upload -------------------------------------------------------------
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """
    VULNERABILITIES HERE
    --------------------
    ❌ No extension check    — .php, .py, .exe accepted alongside images.
    ❌ No magic-byte check   — renaming shell.php to shell.jpg is NOT detected.
    ❌ No secure_filename()  — original filename used, path traversal possible.
    ❌ No size limit         — no MAX_CONTENT_LENGTH set.
    ❌ File saved with original name in web-accessible folder.

    ATTACK TO TRY (extension bypass):
        Upload a file named shell.txt containing any text.
        It is saved to static/uploads/shell.txt and accessible via the browser.

    ATTACK TO TRY (path traversal — test carefully):
        A filename like ../../app_vul.py would attempt to overwrite the app
        source. secure_filename() in app.py prevents this.
    """
    form = UploadForm()
    uploaded_url = None

    if request.method == 'POST':
        file = request.files.get('photo')
        if file and file.filename != '':

            # ❌ VULNERABLE: use the attacker-controlled filename directly
            filename  = file.filename                    # No secure_filename()
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # ❌ No extension check, no magic-byte check, no rename
            file.save(save_path)

            uploaded_url = url_for('static', filename=f'uploads/{filename}')
            flash(f'File uploaded: {filename}', 'success')

    return render_template('upload.html', form=form, uploaded_url=uploaded_url)


# --- Diagnostics (Command Injection) -----------------------------------------
@app.route('/diagnostics', methods=['GET', 'POST'])
@login_required
def diagnostics():
    """
    VULNERABILITY HERE
    ------------------
    ❌ Command Injection — user-supplied IP address concatenated directly into
       a shell command string and executed with shell=True.

    ATTACK TO TRY:
        IP field:  127.0.0.1; id
        IP field:  127.0.0.1; cat /etc/passwd
        IP field:  127.0.0.1; ls -la

    The shell interprets the semicolon as a command separator, so the OS
    runs 'ping -c 2 127.0.0.1' then the injected command.

    app.py fix:  subprocess.run(['ping', '-c', '2', ip], shell=False)
                 Pass args as a list — the shell is never invoked, so
                 metacharacters (;  &  |  $) have no special meaning.
                 Also validate ip with: re.match(r'^\\d{1,3}(\\.\\d{1,3}){3}$', ip)
    """
    output = None
    ip = ''
    if request.method == 'POST':
        ip = request.form.get('ip', '')
        # ❌ VULNERABLE: input concatenated into shell string — OS metacharacters
        #    (;  |  &  &&  ||  $()) allow arbitrary command execution.
        cmd = f"ping -c 2 {ip}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = 'Command timed out.'
        except Exception as e:
            output = f'Error: {e}'

    return render_template('diagnostics.html', output=output, ip=ip)


# --- View Page (File Inclusion / Path Traversal) ------------------------------
@app.route('/page')
def view_page():
    """
    VULNERABILITY HERE
    ------------------
    ❌ Local File Inclusion (LFI) / Path Traversal — the 'file' query parameter
       is joined directly to the 'pages/' base directory without any validation.
       An attacker can use ../ sequences to escape the pages/ directory and read
       any file the web process has permission to open.

    ATTACK TO TRY (in the browser address bar):
        /page?file=help.txt                       (normal — shows help page)
        /page?file=../app_vul.py                  (reads app source code!)
        /page?file=../notes_vul.db                (binary — DB file)
        /page?file=../../etc/passwd               (system file)
        /page?file=../static/uploads/shell.php    (after file-upload attack)

    app.py fix:
        ALLOWED = {'help.txt', 'about.txt', 'faq.txt'}
        if filename not in ALLOWED:
            abort(404)
        Or use: os.path.realpath() to resolve the full path then check it starts
        with the expected base directory before opening.
    """
    filename = request.args.get('file', 'help.txt')
    # ❌ VULNERABLE: no allowlist, no realpath check — any file on the system readable
    filepath = os.path.join('pages', filename)
    try:
        with open(filepath, 'r', errors='replace') as f:
            content = f.read()
    except Exception as e:
        content = f'Error reading file: {e}'

    return render_template('view_page.html', content=content, filename=filename)


# --- Change Password (CSRF demo) ----------------------------------------------
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    VULNERABILITY HERE
    ------------------
    ❌ CSRF — WTF_CSRF_ENABLED is False, so no CSRF token is validated.
       A forged POST request from any website will be accepted as legitimate,
       because the browser automatically sends the session cookie with it.

    ATTACK TO TRY:
        1. Log in as a victim (e.g., admin / password).
        2. While still logged in, open an attacker-controlled HTML file:

           <form id="f" action="http://127.0.0.1:5001/change-password" method="POST">
               <input type="hidden" name="new_password" value="hacked">
               <input type="hidden" name="confirm_password" value="hacked">
           </form>
           <script>document.getElementById('f').submit();</script>

        3. The victim's password is silently changed to 'hacked'.

    app.py fix:  csrf = CSRFProtect(app)  +  {{ form.hidden_tag() }} in the
                 template.  A signed CSRF token is embedded in the form and
                 verified server-side; cross-origin POSTs lack the token and
                 are rejected with HTTP 400.
    """
    if request.method == 'POST':
        new_password     = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # ❌ VULNERABLE: no CSRF token checked, no old-password verification
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
        elif not new_password:
            flash('Password cannot be empty.', 'danger')
        else:
            pw_hash = weak_hash(new_password)
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (pw_hash, session['user_id'])
            )
            db.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('change_password.html')


# =============================================================================
#  ENTRY POINT
# =============================================================================
if __name__ == '__main__':
    init_db()
    # Runs on port 5001 so both app.py (5000) and app_vul.py (5001) can run
    # simultaneously in the same terminal or two terminal windows.
    app.run(debug=True, host='127.0.0.1', port=5001)
