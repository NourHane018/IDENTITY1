# app.py - University Identity & Access Management System (Final Clean Version)
import sqlite3
from datetime import datetime, timedelta
import os, re, secrets, random, string, json, base64, io, smtplib
from email.message import EmailMessage
from functools import wraps
import bcrypt, pyotp, qrcode
from flask import Flask, request, render_template, redirect, jsonify, session, url_for, make_response, flash
from dotenv import load_dotenv

load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SECRET_KEY = os.getenv("SECRET_KEY", 'your-secret-key-here')

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, TEMPLATES_AUTO_RELOAD=True, SESSION_COOKIE_HTTPONLY=True)
app.debug = True

# ======================== CONFIGURATION ========================
class AuthConfig:
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 64
    PASSWORD_COMPLEXITY_REQUIREMENTS = 3
    PASSWORD_HISTORY_LIMIT = 5
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 30
    OTP_LENGTH = 8
    OTP_VALIDITY = 5
    OTP_RATE_LIMIT = 5
    OTP_RESEND_COOLDOWN = 60
    OTP_MAX_ATTEMPTS = 5
    TOTP_TIME_STEP = 30        # Fixed to 30 seconds for Google Authenticator compatibility
    TOTP_DIGITS = 6
    TOTP_BACKUP_CODES_COUNT = 10
    RESET_TOKEN_VALIDITY = 60
    BCRYPT_ROUNDS = 12

    AUTH_LEVELS = {
        'L1': {'name': 'Basic', 'methods': ['password'], 'requires_mfa': False},
        'L2': {'name': 'Standard', 'methods': ['password', 'email_otp'], 'requires_mfa': True},
        'L3': {'name': 'High', 'methods': ['password', 'email_otp', 'totp'], 'requires_mfa': True},
        'L4': {'name': 'Critical', 'methods': ['password', 'email_otp', 'totp', 'security_question'], 'requires_mfa': True}
    }

    SECURITY_QUESTIONS = [
        "What was your first pet's name?",
        "In which city were you born?",
        "What was your childhood nickname?",
        "What is your mother's maiden name?",
        "What was the name of your first school?"
    ]

class IDConfig:
    ID_RANGES = {
        'Undergraduate': {'prefix': 'STU', 'start': 202400001, 'end': 202415000},
        'Continuing Education': {'prefix': 'CED', 'start': 202400001, 'end': 202405000},
        'PhD Candidates': {'prefix': 'PHD', 'start': 202400001, 'end': 202401000},
        'International/Exchange': {'prefix': 'INT', 'start': 202400001, 'end': 202402000},
        'Tenured': {'prefix': 'FAC', 'start': 202400001, 'end': 202401200},
        'Adjunct/Part-time': {'prefix': 'ADJ', 'start': 202400001, 'end': 202400500},
        'Visiting Researchers': {'prefix': 'VIS', 'start': 202400001, 'end': 202400300},
        'Administrative': {'prefix': 'STF', 'start': 202400001, 'end': 202400800},
        'Technical': {'prefix': 'TEC', 'start': 202400001, 'end': 202400400},
        'Temporary': {'prefix': 'TMP', 'start': 202400001, 'end': 202400500},
        'Contractors/Vendors': {'prefix': 'CON', 'start': 202400001, 'end': 202400900},
        'Alumni': {'prefix': 'ALM', 'start': 202400001, 'end': 202420000}
    }

    VALID_TRANSITIONS = {
        'Pending': ['Active'],
        'Active': ['Suspended', 'Inactive'],
        'Suspended': ['Active'],
        'Inactive': ['Archived'],
        'Archived': []
    }

# ======================== DATABASE HELPERS ========================
def get_db_connection(db_name='database.db'):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def init_dbs():
    # Main database (People + Audit)
    with get_db_connection('database.db') as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS People (
                id TEXT PRIMARY KEY,
                type TEXT,
                sub_category TEXT,
                first_name TEXT,
                last_name TEXT,
                dob TEXT,
                place_of_birth TEXT,
                nationality TEXT,
                gender TEXT,
                email TEXT UNIQUE,
                phone TEXT,
                status TEXT,
                status_changed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                student_national_id TEXT,
                student_high_school_diploma_type TEXT,
                student_high_school_diploma_year INTEGER,
                student_high_school_honors TEXT,
                student_major TEXT,
                student_entry_year INTEGER,
                student_status TEXT,
                student_faculty_department TEXT,
                student_group TEXT,
                student_scholarship_status TEXT,
                faculty_rank TEXT,
                faculty_employment_category TEXT,
                faculty_appointment_start_date TEXT,
                faculty_primary_department TEXT,
                faculty_secondary_departments TEXT,
                faculty_office_building TEXT,
                faculty_office_floor TEXT,
                faculty_office_room TEXT,
                faculty_phd_institution TEXT,
                faculty_research_areas TEXT,
                faculty_habilitation_supervise TEXT,
                faculty_contract_type TEXT,
                faculty_contract_start_date TEXT,
                faculty_contract_end_date TEXT,
                faculty_teaching_hours INTEGER,
                staff_assigned_department TEXT,
                staff_job_title TEXT,
                staff_grade TEXT,
                staff_entry_date TEXT,
                external_organization TEXT,
                external_contact_person TEXT,
                is_department_head INTEGER DEFAULT 0,
                is_hr_payroll INTEGER DEFAULT 0,
                contract_expiry_date TEXT
            );
            CREATE TABLE IF NOT EXISTS Audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                changed_at TEXT,
                field TEXT,
                old_value TEXT,
                new_value TEXT
            );
        ''')
        conn.commit()

    # Authentication database
    with get_db_connection('auth.db') as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS AuthUsers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT UNIQUE,
                username TEXT UNIQUE,
                password_hash TEXT,
                auth_level TEXT DEFAULT 'L1',
                mfa_enabled INTEGER DEFAULT 0,
                first_login INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                password_changed_at TEXT,
                password_history TEXT DEFAULT '[]',
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS MFASecrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                method_type TEXT,
                secret TEXT,
                verified INTEGER DEFAULT 0,
                backup_codes TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS SecurityQuestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                question TEXT,
                answer_hash TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS OTPCodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                code TEXT,
                method TEXT,
                expires_at TEXT,
                used INTEGER DEFAULT 0,
                attempts INTEGER DEFAULT 0,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS Sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                person_id TEXT,
                auth_level TEXT,
                created_at TEXT,
                expires_at TEXT,
                last_activity TEXT,
                ip_address TEXT,
                user_agent TEXT,
                remember_me INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS LoginHistory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                session_id TEXT,
                login_time TEXT,
                logout_time TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success INTEGER,
                failure_reason TEXT,
                mfa_used TEXT,
                auth_level_used TEXT
            );
            CREATE TABLE IF NOT EXISTS PasswordResetTokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id TEXT,
                token TEXT,
                expires_at TEXT,
                used INTEGER DEFAULT 0,
                created_at TEXT
            );
        ''')
        conn.commit()
    print("Databases initialized with all required fields.")

# ======================== HELPER FUNCTIONS ========================
def hash_password(pw):
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt(rounds=AuthConfig.BCRYPT_ROUNDS)).decode('utf-8')

def verify_password(pw, h):
    return bcrypt.checkpw(pw.encode('utf-8'), h.encode('utf-8'))

def generate_otp():
    return ''.join(random.choices(string.digits, k=AuthConfig.OTP_LENGTH))

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret, code):
    try:
        totp = pyotp.TOTP(secret, interval=AuthConfig.TOTP_TIME_STEP, digits=AuthConfig.TOTP_DIGITS)
        return totp.verify(code)
    except:
        return False

def generate_backup_codes():
    return [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(AuthConfig.TOTP_BACKUP_CODES_COUNT)]

def hash_answer(ans):
    return bcrypt.hashpw(ans.lower().strip().encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_answer(ans, h):
    return bcrypt.checkpw(ans.lower().strip().encode('utf-8'), h.encode('utf-8'))

def send_email(to, subject, body):
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to
        msg.set_content(body)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email failed: {e}")
        return False

def store_otp(conn, person_id, code, method):
    cur = conn.cursor()
    expires_at = (datetime.now() + timedelta(minutes=AuthConfig.OTP_VALIDITY)).isoformat()
    cur.execute("SELECT COUNT(*) FROM OTPCodes WHERE person_id=? AND method=? AND created_at > ?",
                (person_id, method, (datetime.now() - timedelta(hours=1)).isoformat()))
    if cur.fetchone()[0] >= AuthConfig.OTP_RATE_LIMIT:
        return False, "Too many OTP requests"
    cur.execute("INSERT INTO OTPCodes (person_id, code, method, expires_at, created_at, used, attempts) VALUES (?,?,?,?,?,0,0)",
                (person_id, code, method, expires_at, datetime.now().isoformat()))
    conn.commit()
    return True, None

def verify_otp(conn, person_id, code, method):
    cur = conn.cursor()
    cur.execute("SELECT id, code, attempts, expires_at FROM OTPCodes WHERE person_id=? AND method=? AND used=0 ORDER BY created_at DESC LIMIT 1",
                (person_id, method))
    row = cur.fetchone()
    if not row:
        return False, "No valid OTP"
    otp_id, stored_code, attempts, expires_at = row
    if datetime.now().isoformat() > expires_at:
        cur.execute("UPDATE OTPCodes SET used=1 WHERE id=?", (otp_id,))
        conn.commit()
        return False, "OTP expired"
    if attempts >= AuthConfig.OTP_MAX_ATTEMPTS:
        cur.execute("UPDATE OTPCodes SET used=1 WHERE id=?", (otp_id,))
        conn.commit()
        return False, "Max attempts exceeded"
    if stored_code == code:
        cur.execute("UPDATE OTPCodes SET used=1 WHERE id=?", (otp_id,))
        conn.commit()
        return True, "Success"
    else:
        cur.execute("UPDATE OTPCodes SET attempts=? WHERE id=?", (attempts+1, otp_id))
        conn.commit()
        remaining = AuthConfig.OTP_MAX_ATTEMPTS - attempts - 1
        return False, f"Invalid code. {remaining} attempts left"

def generate_id(sub_category):
    if sub_category not in IDConfig.ID_RANGES:
        year = datetime.now().year
        with get_db_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM People WHERE sub_category=?", (sub_category,)).fetchone()[0]
        return f"TMP{year}{count+1:05d}"
    info = IDConfig.ID_RANGES[sub_category]
    with get_db_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM People WHERE sub_category=?", (sub_category,)).fetchone()[0]
    next_num = info['start'] + count
    if next_num > info['end']:
        raise ValueError(f"No available IDs for {sub_category}")
    return f"{info['prefix']}{next_num}"

def generate_temporary_password():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + '!@#$%^&*'
    return ''.join(random.choices(chars, k=12))

def is_valid_transition(current, new, changed_at=None):
    if current == new:
        return True
    if current not in IDConfig.VALID_TRANSITIONS or new not in IDConfig.VALID_TRANSITIONS[current]:
        return False
    if current == 'Inactive' and new == 'Archived' and changed_at:
        inactive_date = datetime.fromisoformat(changed_at)
        if (datetime.now() - inactive_date).days < 5*365:
            return False
    return True

def validate_user_data(data):
    errors = []
    required_common = ['first_name', 'last_name', 'email', 'dob', 'type', 'sub_category']
    for f in required_common:
        if not data.get(f):
            errors.append(f"{f} is required")
    if data.get('first_name') and len(data['first_name'].strip()) < 2:
        errors.append("First name must be at least 2 characters")
    if data.get('last_name') and len(data['last_name'].strip()) < 2:
        errors.append("Last name must be at least 2 characters")
    email = data.get('email', '').strip().lower()
    if email:
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            errors.append("Invalid email format")
        with get_db_connection() as conn:
            existing = conn.execute("SELECT id FROM People WHERE email=?", (email,)).fetchone()
            if existing:
                errors.append("Email already exists")
    phone = data.get('phone', '').strip()
    if phone and not phone.isdigit():
        errors.append("Phone must contain only digits")
    dob = data.get('dob')
    if dob:
        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d')
            if dob_date > datetime.now():
                errors.append("Date of birth cannot be in the future")
            age = (datetime.now() - dob_date).days / 365.25
            if age < 16:
                errors.append("You must be at least 16 years old")
        except ValueError:
            errors.append("Invalid date format (YYYY-MM-DD)")
    sub_cat = data.get('sub_category', '')
    student_cats = ['Undergraduate', 'Continuing Education', 'PhD Candidates', 'International/Exchange']
    faculty_cats = ['Tenured', 'Adjunct/Part-time', 'Visiting Researchers']
    staff_cats = ['Administrative', 'Technical', 'Temporary']
    external_cats = ['Contractors/Vendors', 'Alumni']
    if sub_cat in student_cats:
        if not data.get('student_major'):
            errors.append("Major/Program is required for students")
        if not data.get('student_entry_year'):
            errors.append("Entry year is required for students")
        if not data.get('student_status'):
            errors.append("Student status is required")
        if not data.get('student_faculty_department'):
            errors.append("Faculty & Department is required for students")
    if sub_cat in faculty_cats:
        if not data.get('faculty_rank'):
            errors.append("Rank is required for faculty")
        if not data.get('faculty_primary_department'):
            errors.append("Primary department is required for faculty")
        if not data.get('faculty_appointment_start_date'):
            errors.append("Appointment start date is required for faculty")
    if sub_cat in staff_cats:
        if not data.get('staff_assigned_department'):
            errors.append("Assigned department is required for staff")
        if not data.get('staff_job_title'):
            errors.append("Job title is required for staff")
        if not data.get('staff_entry_date'):
            errors.append("Date of entry is required for staff")
    if sub_cat in external_cats:
        if not data.get('external_organization'):
            errors.append("Organization is required for external members")
    return errors

def validate_password_strength(password, user_info=None):
    errors = []
    if len(password) < AuthConfig.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {AuthConfig.PASSWORD_MIN_LENGTH} characters")
    if len(password) > AuthConfig.PASSWORD_MAX_LENGTH:
        errors.append(f"Password cannot exceed {AuthConfig.PASSWORD_MAX_LENGTH} characters")
    categories = sum([
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[0-9]', password)),
        bool(re.search(r'[!@#$%^&*]', password))
    ])
    if categories < AuthConfig.PASSWORD_COMPLEXITY_REQUIREMENTS:
        errors.append("Password must contain at least 3 of: uppercase, lowercase, digit, special character (!@#$%^&*)")
    if user_info:
        for field in ['first_name', 'last_name']:
            if user_info.get(field) and user_info[field].lower() in password.lower():
                errors.append(f"Password cannot contain your {field}")
        if user_info.get('email') and user_info['email'].split('@')[0].lower() in password.lower():
            errors.append("Password cannot contain your username")
        if user_info.get('dob') and user_info['dob'] in password:
            errors.append("Password cannot contain your date of birth")
    return errors

def check_password_history(conn, person_id, new_hash):
    cur = conn.cursor()
    cur.execute("SELECT password_history FROM AuthUsers WHERE person_id=?", (person_id,))
    row = cur.fetchone()
    if row and row[0]:
        history = json.loads(row[0])
        return new_hash in history
    return False

def update_password_history(conn, person_id, new_hash):
    cur = conn.cursor()
    cur.execute("SELECT password_history FROM AuthUsers WHERE person_id=?", (person_id,))
    row = cur.fetchone()
    history = json.loads(row[0]) if row and row[0] else []
    history.append(new_hash)
    if len(history) > AuthConfig.PASSWORD_HISTORY_LIMIT:
        history = history[-AuthConfig.PASSWORD_HISTORY_LIMIT:]
    cur.execute("UPDATE AuthUsers SET password_history=? WHERE person_id=?", (json.dumps(history), person_id))
    conn.commit()

def check_account_lockout(conn, person_id):
    cur = conn.cursor()
    cur.execute("SELECT failed_attempts, locked_until FROM AuthUsers WHERE person_id=?", (person_id,))
    row = cur.fetchone()
    if row and row[1]:
        locked_until = datetime.fromisoformat(row[1])
        if datetime.now() < locked_until:
            return True, locked_until
    return False, None

def increment_failed_attempts(conn, person_id):
    cur = conn.cursor()
    cur.execute("SELECT failed_attempts FROM AuthUsers WHERE person_id=?", (person_id,))
    attempts = (cur.fetchone()[0] or 0) + 1
    if attempts >= AuthConfig.MAX_LOGIN_ATTEMPTS:
        locked_until = (datetime.now() + timedelta(minutes=AuthConfig.LOCKOUT_DURATION)).isoformat()
        cur.execute("UPDATE AuthUsers SET failed_attempts=?, locked_until=?, updated_at=? WHERE person_id=?", 
                    (attempts, locked_until, datetime.now().isoformat(), person_id))
    else:
        cur.execute("UPDATE AuthUsers SET failed_attempts=?, updated_at=? WHERE person_id=?", 
                    (attempts, datetime.now().isoformat(), person_id))
    conn.commit()

def reset_failed_attempts(conn, person_id):
    cur = conn.cursor()
    cur.execute("UPDATE AuthUsers SET failed_attempts=0, locked_until=NULL, updated_at=? WHERE person_id=?", 
                (datetime.now().isoformat(), person_id))
    conn.commit()

def create_session(person_id, auth_level, ip, ua, remember_me=False):
    session_id = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + (timedelta(days=7) if remember_me else timedelta(hours=24))).isoformat()
    conn = get_db_connection('auth.db')
    conn.execute("INSERT INTO Sessions (session_id, person_id, auth_level, created_at, expires_at, last_activity, ip_address, user_agent, remember_me) VALUES (?,?,?,?,?,?,?,?,?)",
                 (session_id, person_id, auth_level, datetime.now().isoformat(), expires_at, datetime.now().isoformat(), ip, ua, 1 if remember_me else 0))
    conn.commit()
    conn.close()
    return session_id

def validate_session(session_id):
    if not session_id:
        return None
    conn = get_db_connection('auth.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM Sessions WHERE session_id=? AND expires_at > ?", (session_id, datetime.now().isoformat()))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE Sessions SET last_activity=? WHERE session_id=?", (datetime.now().isoformat(), session_id))
        conn.commit()
    conn.close()
    return row

def invalidate_user_sessions(conn, person_id):
    conn.execute("UPDATE Sessions SET expires_at=? WHERE person_id=? AND expires_at > ?", 
                 (datetime.now().isoformat(), person_id, datetime.now().isoformat()))
    conn.commit()

def log_authentication_event(person_id, session_id, ip, success, failure_reason=None, mfa_used=None, auth_level_used=None):
    conn = get_db_connection('auth.db')
    conn.execute("INSERT INTO LoginHistory (person_id, session_id, login_time, ip_address, user_agent, success, failure_reason, mfa_used, auth_level_used) VALUES (?,?,?,?,?,?,?,?,?)",
                 (person_id, session_id, datetime.now().isoformat(), ip, request.headers.get('User-Agent'), 1 if success else 0, failure_reason, mfa_used, auth_level_used))
    conn.commit()
    conn.close()

def get_user_auth_level(user_type, sub_category):
    if user_type == 'IT Admin':
        return 'L2'   # Will be upgraded after MFA setup
    if user_type in ['Faculty', 'Admin Staff', 'Staff', 'Researcher']:
        return 'L2'
    if user_type == 'Student' and sub_category == 'International/Exchange':
        return 'L2'
    return 'L1'

def get_effective_auth_level(person_id):
    with get_db_connection('auth.db') as conn_auth, get_db_connection() as conn_main:
        user = conn_main.execute("SELECT type, sub_category, is_department_head, is_hr_payroll, contract_expiry_date FROM People WHERE id=?", (person_id,)).fetchone()
        if not user:
            return 'L1'
        user_type, sub_cat, is_dept_head, is_hr, contract_expiry = user

        mfa_methods = conn_auth.execute("SELECT method_type FROM MFASecrets WHERE person_id=? AND verified=1", (person_id,)).fetchall()
        mfa_types = [m[0] for m in mfa_methods]
        has_totp = 'totp' in mfa_types
        has_email_otp = 'email_otp' in mfa_types
        has_security = conn_auth.execute("SELECT COUNT(*) FROM SecurityQuestions WHERE person_id=?", (person_id,)).fetchone()[0] >= 2

        # Check contract expiry for contractors
        if user_type == 'Contractor' and contract_expiry:
            expiry_date = datetime.fromisoformat(contract_expiry)
            if datetime.now() > expiry_date:
                return 'L1'

        # IT Admin
        if user_type == 'IT Admin':
            if has_totp and has_security:
                return 'L4'
            else:
                return 'L2'

        # Faculty, Admin Staff, Researchers
        if user_type in ['Faculty', 'Admin Staff', 'Staff', 'Researcher']:
            mandatory_l3 = (user_type == 'Faculty' and is_dept_head) or (user_type in ['Admin Staff', 'Staff'] and is_hr)
            if mandatory_l3:
                if has_totp:
                    return 'L3'
                else:
                    return 'L2'
            else:
                if has_totp and has_security:
                    return 'L4'
                elif has_totp:
                    return 'L3'
                else:
                    return 'L2'

        # Students
        if user_type == 'Student':
            if sub_cat == 'International/Exchange':
                return 'L2'
            else:
                if has_email_otp:
                    return 'L2'
                else:
                    return 'L1'

        # Contractors
        if user_type == 'Contractor':
            if has_email_otp:
                return 'L2'
            else:
                return 'L1'

        return 'L1'

def upgrade_auth_level_if_needed(person_id):
    new_level = get_effective_auth_level(person_id)
    conn = get_db_connection('auth.db')
    conn.execute("UPDATE AuthUsers SET auth_level=?, updated_at=? WHERE person_id=?", (new_level, datetime.now().isoformat(), person_id))
    conn.commit()
    conn.close()
    return new_level

def create_auth_user(person_id, username, user_type, sub_category):
    conn = get_db_connection('auth.db')
    temp_pw = generate_temporary_password()
    temp_hash = hash_password(temp_pw)
    auth_level = get_user_auth_level(user_type, sub_category)
    now = datetime.now().isoformat()
    existing = conn.execute("SELECT person_id FROM AuthUsers WHERE person_id=? OR username=?", (person_id, username)).fetchone()
    if existing:
        conn.execute("UPDATE AuthUsers SET password_hash=?, auth_level=?, first_login=1, updated_at=? WHERE person_id=?", 
                     (temp_hash, auth_level, now, person_id))
    else:
        conn.execute("INSERT INTO AuthUsers (person_id, username, password_hash, auth_level, first_login, created_at, updated_at) VALUES (?,?,?,?,1,?,?)",
                     (person_id, username, temp_hash, auth_level, now, now))
    conn.commit()
    conn.close()
    return temp_pw

# ======================== DECORATORS ========================
def auth_required(f):
    @wraps(f)
    def dec(*args, **kwargs):
        if not validate_session(request.cookies.get('session_id')):
            flash('Please login to access this page', 'warning')
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return dec

def admin_required(f):
    @wraps(f)
    def dec(*args, **kwargs):
        sess = validate_session(request.cookies.get('session_id'))
        if not sess:
            flash('Please login', 'warning')
            return redirect(url_for('auth_login'))
        with get_db_connection() as conn:
            typ = conn.execute("SELECT type FROM People WHERE id=?", (sess[2],)).fetchone()
            if not typ or typ[0] != 'IT Admin':
                flash('Admin access required', 'error')
                return redirect(url_for('index'))
        return f(*args, **kwargs)
    return dec

# ======================== ROUTES - IDENTITY MANAGEMENT ========================
@app.route("/")
def index():
    sess = validate_session(request.cookies.get('session_id'))
    user_type = None
    if sess:
        with get_db_connection() as conn:
            row = conn.execute("SELECT type FROM People WHERE id=?", (sess[2],)).fetchone()
            if row:
                user_type = row[0]
    return render_template("index.html", logged_in=sess is not None, user_type=user_type)

@app.route("/create", methods=["GET","POST"])
def create():
    if request.method == "POST":
        data = request.form.to_dict()
        errors = validate_user_data(data)
        if errors:
            return render_template("create.html", errors=errors, form_data=data)
        try:
            uid = generate_id(data['sub_category'])
        except ValueError as e:
            return render_template("create.html", errors=[str(e)], form_data=data)

        conn = get_db_connection()
        now = datetime.now().isoformat()
        fields = [
            'id', 'type', 'sub_category', 'first_name', 'last_name', 'dob', 'place_of_birth',
            'nationality', 'gender', 'email', 'phone', 'status', 'status_changed_at',
            'student_national_id', 'student_high_school_diploma_type', 'student_high_school_diploma_year',
            'student_high_school_honors', 'student_major', 'student_entry_year', 'student_status',
            'student_faculty_department', 'student_group', 'student_scholarship_status',
            'faculty_rank', 'faculty_employment_category', 'faculty_appointment_start_date',
            'faculty_primary_department', 'faculty_secondary_departments', 'faculty_office_building',
            'faculty_office_floor', 'faculty_office_room', 'faculty_phd_institution', 'faculty_research_areas',
            'faculty_habilitation_supervise', 'faculty_contract_type', 'faculty_contract_start_date',
            'faculty_contract_end_date', 'faculty_teaching_hours',
            'staff_assigned_department', 'staff_job_title', 'staff_grade', 'staff_entry_date',
            'external_organization', 'external_contact_person',
            'is_department_head', 'is_hr_payroll', 'contract_expiry_date'
        ]
        values = [uid] + [data.get(field) for field in fields[1:]]
        # Convert checkbox values to 0/1
        if 'is_department_head' in data:
            values[fields.index('is_department_head')] = 1 if data.get('is_department_head') == 'on' else 0
        if 'is_hr_payroll' in data:
            values[fields.index('is_hr_payroll')] = 1 if data.get('is_hr_payroll') == 'on' else 0
        # Set status_changed_at
        values[fields.index('status_changed_at')] = now
        placeholders = ','.join(['?']*len(fields))
        conn.execute(f"INSERT INTO People ({','.join(fields)}) VALUES ({placeholders})", values)
        conn.commit()
        conn.close()

        temp_pw = create_auth_user(uid, data['email'].lower(), data['type'], data['sub_category'])
        send_email(data['email'], "University Identity Created",
                   f"Hello {data['first_name']} {data['last_name']},\n\nYour ID: {uid}\nTemporary password: {temp_pw}\n\nYou must change your password on first login.\n\nUniversity IAM System")
        flash(f"Identity created successfully! ID: {uid}", "success")
        return render_template("success.html", uid=uid, temp_password=temp_pw, email=data['email'])
    return render_template("create.html")

@app.route("/view_all")
@admin_required
def view_all():
    conn = get_db_connection()
    people = conn.execute("SELECT * FROM People ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("view_all.html", people=people)

@app.route("/view/<uid>")
@auth_required
def view(uid):
    conn = get_db_connection()
    person = conn.execute("SELECT * FROM People WHERE id=?", (uid,)).fetchone()
    audits = conn.execute("SELECT * FROM Audit WHERE person_id=? ORDER BY changed_at DESC", (uid,)).fetchall()
    conn.close()
    if not person:
        return "Identity not found", 404
    return render_template("view.html", person=person, audits=audits)

@app.route("/edit/<uid>", methods=["GET","POST"])
@admin_required
def edit(uid):
    conn = get_db_connection()
    person = conn.execute("SELECT * FROM People WHERE id=?", (uid,)).fetchone()
    if not person:
        conn.close()
        return "Not found", 404
    if request.method == "POST":
        if person['status'] == 'Archived':
            conn.close()
            return render_template("edit.html", person=person, error="Archived identities cannot be edited")
        new_status = request.form.get('status')
        if new_status and new_status != person['status']:
            if not is_valid_transition(person['status'], new_status, person['status_changed_at']):
                conn.close()
                return render_template("edit.html", person=person, error=f"Invalid status transition from {person['status']} to {new_status}")
            conn.execute("UPDATE People SET status=?, status_changed_at=? WHERE id=?", (new_status, datetime.now().isoformat(), uid))
        # Update other fields (excluding immutable ones)
        for key in person.keys():
            if key not in ['id', 'status', 'status_changed_at', 'created_at'] and key in request.form:
                new_val = request.form.get(key)
                old_val = person[key] or ''
                if str(new_val) != str(old_val):
                    conn.execute(f"UPDATE People SET {key}=? WHERE id=?", (new_val, uid))
                    conn.execute("INSERT INTO Audit (person_id, changed_at, field, old_value, new_value) VALUES (?,?,?,?,?)",
                                 (uid, datetime.now().isoformat(), key, old_val, new_val))
        conn.commit()
        conn.close()
        flash("Identity updated successfully", "success")
        return redirect(url_for('view', uid=uid))
    conn.close()
    return render_template("edit.html", person=person)

@app.route("/delete/<uid>", methods=["POST"])
@admin_required
def delete(uid):
    conn = get_db_connection()
    person = conn.execute("SELECT status FROM People WHERE id=?", (uid,)).fetchone()
    if person and person['status'] in ['Pending', 'Active']:
        conn.execute("UPDATE People SET status='Inactive', status_changed_at=? WHERE id=?", (datetime.now().isoformat(), uid))
        conn.execute("INSERT INTO Audit (person_id, changed_at, field, old_value, new_value) VALUES (?,?,?,?,?)",
                     (uid, datetime.now().isoformat(), 'status', person['status'], 'Inactive'))
        conn.commit()
        flash(f"Identity {uid} set to Inactive", "info")
    else:
        flash("Cannot delete/change status", "error")
    conn.close()
    return redirect(url_for('view_all'))

@app.route("/search", methods=["GET","POST"])
@admin_required
def search():
    results = []
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        type_filter = request.form.get("type_filter", "")
        status_filter = request.form.get("status_filter", "")
        conn = get_db_connection()
        sql = "SELECT * FROM People WHERE 1=1"
        params = []
        if query:
            sql += " AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR id LIKE ?)"
            params.extend([f"%{query}%"]*4)
        if type_filter:
            sql += " AND type=?"
            params.append(type_filter)
        if status_filter:
            sql += " AND status=?"
            params.append(status_filter)
        results = conn.execute(sql, params).fetchall()
        conn.close()
    return render_template("search.html", results=results)

# ======================== AUTHENTICATION ROUTES ========================
@app.route('/auth/login', methods=['GET','POST'])
def auth_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember_me') == 'on'
        ip = request.remote_addr
        ua = request.headers.get('User-Agent')
        for k in ['mfa_person_id','mfa_email','mfa_auth_level','mfa_first_login','mfa_required_methods','mfa_completed_steps', 'force_mfa_setup']:
            session.pop(k, None)

        with get_db_connection() as conn_main, get_db_connection('auth.db') as conn_auth:
            person = conn_main.execute("SELECT id, email, first_name, last_name, type, sub_category, is_department_head, is_hr_payroll, contract_expiry_date FROM People WHERE email=?", (username,)).fetchone()
            if not person:
                log_authentication_event(None, None, ip, False, "User not found")
                flash("Invalid credentials", "error")
                return render_template("auth_login.html")
            pid, email, fname, lname, utype, subcat, is_dept_head, is_hr, contract_expiry = person

            # Check contractor expiry
            if utype == 'Contractor' and contract_expiry:
                expiry_date = datetime.fromisoformat(contract_expiry)
                if datetime.now() > expiry_date:
                    flash("Your contract has expired. Please contact administration.", "error")
                    return render_template("auth_login.html")

            locked, until = check_account_lockout(conn_auth, pid)
            if locked:
                flash(f"Account locked until {until.strftime('%H:%M:%S')}", "error")
                return render_template("auth_login.html")

            auth = conn_auth.execute("SELECT password_hash, auth_level, first_login FROM AuthUsers WHERE person_id=?", (pid,)).fetchone()
            if not auth or not verify_password(password, auth[0]):
                increment_failed_attempts(conn_auth, pid)
                log_authentication_event(pid, None, ip, False, "Invalid password")
                flash("Invalid credentials", "error")
                return render_template("auth_login.html")

            reset_failed_attempts(conn_auth, pid)
            auth_level = auth[1]
            first_login = auth[2]

            required_level = get_effective_auth_level(pid)
            if required_level != 'L1':
                session['mfa_person_id'] = pid
                session['mfa_email'] = email
                session['mfa_auth_level'] = auth_level
                session['mfa_first_login'] = first_login
                methods = AuthConfig.AUTH_LEVELS[required_level]['methods'][1:]
                session['mfa_required_methods'] = methods
                session['mfa_completed_steps'] = []
                if 'email_otp' in methods:
                    otp = generate_otp()
                    store_otp(conn_auth, pid, otp, 'email_otp')
                    send_email(email, "Your OTP code", f"Code: {otp} (valid {AuthConfig.OTP_VALIDITY} minutes)")
                return redirect(url_for('auth_mfa'))

            sess_id = create_session(pid, auth_level, ip, ua, remember)
            log_authentication_event(pid, sess_id, ip, True, None, "No", auth_level)
            if first_login:
                session['temp_person_id'] = pid
                return redirect(url_for('auth_change_password', first_login=True))
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('session_id', sess_id, httponly=True, max_age=7*86400 if remember else 86400)
            flash("Login successful", "success")
            return resp
    return render_template("auth_login.html")

@app.route('/auth/mfa', methods=['GET','POST'])
def auth_mfa():
    if 'mfa_person_id' not in session:
        return redirect(url_for('auth_login'))
    pid = session['mfa_person_id']
    email = session['mfa_email']
    required = session.get('mfa_required_methods', [])
    completed = session.get('mfa_completed_steps', [])
    remaining = [m for m in required if m not in completed]

    if not remaining:
        with get_db_connection('auth.db') as conn:
            auth_level = conn.execute("SELECT auth_level, first_login FROM AuthUsers WHERE person_id=?", (pid,)).fetchone()
            sess_id = create_session(pid, auth_level[0], request.remote_addr, request.headers.get('User-Agent'))
            log_authentication_event(pid, sess_id, request.remote_addr, True, None, ','.join(completed), auth_level[0])
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('session_id', sess_id, httponly=True, max_age=86400)
            if auth_level[1]:
                session['temp_person_id'] = pid
                return redirect(url_for('auth_change_password', first_login=True))
            flash("Login successful", "success")
            return resp

    if request.method == 'POST':
        method = request.form.get('method')
        code = request.form.get('code')
        conn = get_db_connection('auth.db')
        verified = False
        msg = ""
        if method in ['otp', 'email_otp']:
            verified, msg = verify_otp(conn, pid, code, 'email_otp')
        elif method == 'totp':
            secret_row = conn.execute("SELECT secret FROM MFASecrets WHERE person_id=? AND method_type='totp' AND verified=1", (pid,)).fetchone()
            if secret_row and verify_totp(secret_row[0], code):
                verified = True
        elif method == 'security_question':
            q = request.form.get('question')
            a = request.form.get('answer')
            row = conn.execute("SELECT answer_hash FROM SecurityQuestions WHERE person_id=? AND question=?", (pid, q)).fetchone()
            if row and verify_answer(a, row[0]):
                verified = True
        conn.close()
        if verified:
            session['mfa_completed_steps'].append(method)
            session.modified = True
            return redirect(url_for('auth_mfa'))
        else:
            flash(f"Verification failed for {method}: {msg}", "error")

    current_method = remaining[0]
    conn = get_db_connection('auth.db')
    security_qs = []
    if current_method == 'security_question':
        rows = conn.execute("SELECT question FROM SecurityQuestions WHERE person_id=?", (pid,)).fetchall()
        security_qs = [r[0] for r in rows]
    conn.close()
    return render_template("auth_mfa.html", email=email, current_method=current_method,
                           security_questions=security_qs, completed=completed)

@app.route('/auth/resend_otp', methods=['POST'])
def auth_resend_otp():
    if 'mfa_person_id' not in session:
        return jsonify(success=False, error="No session")
    pid = session['mfa_person_id']
    email = session['mfa_email']
    otp = generate_otp()
    conn = get_db_connection('auth.db')
    success, err = store_otp(conn, pid, otp, 'email_otp')
    conn.close()
    if success:
        send_email(email, "Your OTP code", f"Code: {otp} (valid {AuthConfig.OTP_VALIDITY} minutes)")
    return jsonify(success=success, error=err)

@app.route('/auth/change_password', methods=['GET','POST'])
def auth_change_password():
    first_login = request.args.get('first_login')
    pid = None
    if first_login and 'temp_person_id' in session:
        pid = session['temp_person_id']
    else:
        sess = validate_session(request.cookies.get('session_id'))
        if sess:
            pid = sess[2]
    if not pid:
        return redirect(url_for('auth_login'))
    if request.method == 'POST':
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if new != confirm:
            return render_template("auth_change_password.html", error="Passwords do not match", first_login=first_login)
        with get_db_connection() as conn_main, get_db_connection('auth.db') as conn_auth:
            user = conn_main.execute("SELECT first_name, last_name, email, dob FROM People WHERE id=?", (pid,)).fetchone()
            user_info = {'first_name': user[0], 'last_name': user[1], 'email': user[2], 'dob': user[3]} if user else {}
            errors = validate_password_strength(new, user_info)
            if errors:
                return render_template("auth_change_password.html", error='; '.join(errors), first_login=first_login)
            new_hash = hash_password(new)
            if check_password_history(conn_auth, pid, new_hash):
                return render_template("auth_change_password.html", error="Password has been used recently", first_login=first_login)
            conn_auth.execute("UPDATE AuthUsers SET password_hash=?, password_changed_at=?, first_login=0, updated_at=? WHERE person_id=?",
                              (new_hash, datetime.now().isoformat(), datetime.now().isoformat(), pid))
            update_password_history(conn_auth, pid, new_hash)
            invalidate_user_sessions(conn_auth, pid)
            conn_auth.commit()
            if user:
                send_email(user[2], "Password changed", f"Dear {user[0]}, your password was changed from IP {request.remote_addr}.")
        session.pop('temp_person_id', None)
        flash("Password changed successfully. Please login again.", "success")
        return redirect(url_for('auth_login'))
    return render_template("auth_change_password.html", first_login=first_login)

@app.route('/auth/forgot_password', methods=['GET','POST'])
def auth_forgot_password():
    if request.method == 'POST':
        email = request.form.get('username')
        with get_db_connection() as conn_main, get_db_connection('auth.db') as conn_auth:
            person = conn_main.execute("SELECT id, first_name FROM People WHERE email=?", (email,)).fetchone()
            if person:
                token = secrets.token_urlsafe(32)
                expires = (datetime.now() + timedelta(minutes=AuthConfig.RESET_TOKEN_VALIDITY)).isoformat()
                conn_auth.execute("INSERT INTO PasswordResetTokens (person_id, token, expires_at, created_at) VALUES (?,?,?,?)",
                                  (person[0], token, expires, datetime.now().isoformat()))
                conn_auth.commit()
                reset_link = f"http://localhost:5000/auth/reset_password/{token}"
                send_email(email, "Password Reset", f"Click the link to reset your password: {reset_link}\n\nValid for {AuthConfig.RESET_TOKEN_VALIDITY} minutes.")
            flash("If an account exists, a reset link has been sent to your email.", "info")
            return redirect(url_for('auth_forgot_password'))
    return render_template("auth_forgot_password.html")

@app.route('/auth/reset_password/<token>', methods=['GET','POST'])
def auth_reset_password(token):
    conn_auth = get_db_connection('auth.db')
    row = conn_auth.execute("SELECT person_id FROM PasswordResetTokens WHERE token=? AND used=0 AND expires_at > ?", (token, datetime.now().isoformat())).fetchone()
    if not row:
        conn_auth.close()
        flash("Invalid or expired token", "error")
        return redirect(url_for('auth_forgot_password'))
    pid = row[0]
    if request.method == 'POST':
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if new != confirm:
            return render_template("auth_reset_password.html", error="Passwords do not match")
        with get_db_connection() as conn_main:
            user = conn_main.execute("SELECT first_name, last_name, email FROM People WHERE id=?", (pid,)).fetchone()
            user_info = {'first_name': user[0], 'last_name': user[1], 'email': user[2]} if user else {}
            errors = validate_password_strength(new, user_info)
            if errors:
                return render_template("auth_reset_password.html", error='; '.join(errors))
            new_hash = hash_password(new)
            if check_password_history(conn_auth, pid, new_hash):
                return render_template("auth_reset_password.html", error="Password has been used recently")
            conn_auth.execute("UPDATE AuthUsers SET password_hash=?, password_changed_at=?, first_login=0, updated_at=? WHERE person_id=?",
                              (new_hash, datetime.now().isoformat(), datetime.now().isoformat(), pid))
            update_password_history(conn_auth, pid, new_hash)
            conn_auth.execute("UPDATE PasswordResetTokens SET used=1 WHERE token=?", (token,))
            invalidate_user_sessions(conn_auth, pid)
            conn_auth.commit()
            if user:
                send_email(user[2], "Password reset", f"Your password was reset from IP {request.remote_addr}.")
        conn_auth.close()
        flash("Password reset successfully. Please login.", "success")
        return redirect(url_for('auth_login'))
    conn_auth.close()
    return render_template("auth_reset_password.html")

@app.route('/auth/logout')
def auth_logout():
    sid = request.cookies.get('session_id')
    if sid:
        conn = get_db_connection('auth.db')
        conn.execute("UPDATE Sessions SET expires_at=? WHERE session_id=?", (datetime.now().isoformat(), sid))
        conn.commit()
        conn.close()
    session.clear()
    resp = make_response(redirect(url_for('auth_login')))
    resp.delete_cookie('session_id')
    flash("You have been logged out", "info")
    return resp

@app.route('/auth/security_dashboard')
@auth_required
def auth_security_dashboard():
    sid = request.cookies.get('session_id')
    sess = validate_session(sid)
    pid = sess[2]
    with get_db_connection() as conn_main, get_db_connection('auth.db') as conn_auth:
        user = conn_main.execute("SELECT first_name, last_name, email, type FROM People WHERE id=?", (pid,)).fetchone()
        auth_info = conn_auth.execute("SELECT auth_level, password_changed_at, first_login, mfa_enabled FROM AuthUsers WHERE person_id=?", (pid,)).fetchone()
        mfa_methods = conn_auth.execute("SELECT method_type, verified FROM MFASecrets WHERE person_id=?", (pid,)).fetchall()
        history = conn_auth.execute("SELECT login_time, ip_address, success, failure_reason, mfa_used, auth_level_used FROM LoginHistory WHERE person_id=? ORDER BY login_time DESC LIMIT 20", (pid,)).fetchall()
    return render_template("auth_security_dashboard.html", user=user, auth_info=auth_info, mfa_methods=mfa_methods, history=history)
@app.route('/auth/setup_mfa', methods=['GET','POST'])
@auth_required
def auth_setup_mfa():
    sid = request.cookies.get('session_id')
    pid = validate_session(sid)[2]
    force = session.pop('force_mfa_setup', False)
    
    # جلب نوع المستخدم من قاعدة البيانات
    with get_db_connection() as conn_main:
        user = conn_main.execute("SELECT type FROM People WHERE id=?", (pid,)).fetchone()
        user_type = user[0] if user else None
    
    if request.method == 'POST':
        method = request.form.get('method')
        if method == 'totp':
            secret = generate_totp_secret()
            with get_db_connection() as conn_main:
                email = conn_main.execute("SELECT email FROM People WHERE id=?", (pid,)).fetchone()[0]
            uri = pyotp.totp.TOTP(secret, interval=AuthConfig.TOTP_TIME_STEP, digits=AuthConfig.TOTP_DIGITS).provisioning_uri(name=email, issuer_name="University")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            qr_code = base64.b64encode(buffered.getvalue()).decode()
            conn = get_db_connection('auth.db')
            conn.execute("DELETE FROM MFASecrets WHERE person_id=? AND method_type='totp' AND verified=0", (pid,))
            conn.execute("INSERT INTO MFASecrets (person_id, method_type, secret, verified, created_at) VALUES (?,?,?,0,?)",
                         (pid, 'totp', secret, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return render_template("auth_setup_totp.html", secret=secret, qr_code=qr_code, force=force)
        elif method == 'security_question':
            return render_template("auth_setup_security.html", questions=AuthConfig.SECURITY_QUESTIONS, force=force)
    
    return render_template("auth_setup_mfa.html", force=force, user_type=user_type)

@app.route('/auth/verify_totp', methods=['POST'])
@auth_required
def auth_verify_totp():
    sid = request.cookies.get('session_id')
    pid = validate_session(sid)[2]
    code = request.form.get('code')
    force = request.form.get('force') == 'true'
    conn = get_db_connection('auth.db')
    secret_row = conn.execute("SELECT secret FROM MFASecrets WHERE person_id=? AND method_type='totp' AND verified=0", (pid,)).fetchone()
    if not secret_row:
        conn.close()
        return jsonify(success=False, error="No TOTP setup found")
    if verify_totp(secret_row[0], code):
        conn.execute("UPDATE MFASecrets SET verified=1 WHERE person_id=? AND method_type='totp'", (pid,))
        backup = generate_backup_codes()
        conn.execute("UPDATE MFASecrets SET backup_codes=? WHERE person_id=? AND method_type='totp'", (json.dumps(backup), pid))
        conn.commit()
        new_level = upgrade_auth_level_if_needed(pid)
        conn.close()
        if force:
            return redirect(url_for('auth_setup_mfa', method='security_question', force=True))
        return render_template("auth_backup_codes.html", backup_codes=backup, new_level=new_level)
    conn.close()
    return jsonify(success=False, error="Invalid TOTP code")

@app.route('/auth/setup_security', methods=['POST'])
@auth_required
def auth_setup_security():
    sid = request.cookies.get('session_id')
    pid = validate_session(sid)[2]
    force = request.form.get('force') == 'true'
    q1, a1 = request.form.get('question1'), request.form.get('answer1')
    q2, a2 = request.form.get('question2'), request.form.get('answer2')
    if not all([q1, a1, q2, a2]):
        flash("Please answer both security questions", "error")
        return redirect(url_for('auth_setup_mfa'))
    conn = get_db_connection('auth.db')
    conn.execute("DELETE FROM SecurityQuestions WHERE person_id=?", (pid,))
    for q, a in [(q1, a1), (q2, a2)]:
        conn.execute("INSERT INTO SecurityQuestions (person_id, question, answer_hash, created_at) VALUES (?,?,?,?)",
                     (pid, q, hash_answer(a), datetime.now().isoformat()))
    conn.commit()
    conn.close()
    upgrade_auth_level_if_needed(pid)
    if force:
        flash("MFA setup complete. You can now log in.", "success")
        return redirect(url_for('auth_login'))
    flash("Security questions saved successfully", "success")
    return redirect(url_for('auth_security_dashboard'))

# ======================== ADMIN ROUTES ========================
@app.route('/admin/auth/dashboard')
@admin_required
def admin_auth_dashboard():
    with get_db_connection('auth.db') as conn_auth, get_db_connection() as conn_main:
        users = []
        for u in conn_auth.execute("SELECT person_id, username, auth_level, mfa_enabled, first_login, failed_attempts, locked_until FROM AuthUsers ORDER BY created_at DESC").fetchall():
            p = conn_main.execute("SELECT email, first_name, last_name, type FROM People WHERE id=?", (u['person_id'],)).fetchone()
            if p:
                users.append({**dict(u), 'email': p['email'], 'first_name': p['first_name'], 'last_name': p['last_name'], 'type': p['type']})
        attempts = conn_auth.execute("SELECT * FROM LoginHistory ORDER BY login_time DESC LIMIT 50").fetchall()
        audit = conn_auth.execute("SELECT * FROM LoginHistory ORDER BY login_time DESC LIMIT 100").fetchall()
    return render_template("admin_auth_dashboard.html", users=users, recent_attempts=attempts, audit_log=audit)

@app.route('/admin/auth/unlock/<person_id>', methods=['POST'])
@admin_required
def admin_unlock_account(person_id):
    conn = get_db_connection('auth.db')
    conn.execute("UPDATE AuthUsers SET failed_attempts=0, locked_until=NULL WHERE person_id=?", (person_id,))
    conn.commit()
    conn.close()
    return jsonify(success=True)

@app.route('/admin/auth/login_history')
@admin_required
def admin_login_history():
    conn_auth = get_db_connection('auth.db')
    conn_main = get_db_connection()
    history = conn_auth.execute("""
        SELECT l.*, p.email, p.first_name, p.last_name, p.type
        FROM LoginHistory l
        LEFT JOIN People p ON l.person_id = p.id
        ORDER BY l.login_time DESC LIMIT 200
    """).fetchall()
    conn_auth.close()
    conn_main.close()
    return render_template("admin_login_history.html", history=history)

# ======================== RUN ========================
if __name__ == "__main__":
    init_dbs()
    print("="*70)
    print("University Identity & Access Management System")
    print("Running at http://127.0.0.1:5000")
    print("Admin login required for some features (IT Admin type)")
    print("="*70)
    app.run(debug=True, host="0.0.0.0", port=5000)