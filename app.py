from flask import Flask, render_template, request, redirect, url_for, session
from datetime import date, timedelta
import pyodbc
import bcrypt
import os
from dotenv import load_dotenv


app = Flask(__name__)
app.secret_key = "secret_gym_key"

@app.template_filter('dateformat')
def dateformat(value):
    if value is None:
        return ''
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d')
    return str(value)[:10]

load_dotenv()

SERVER = os.getenv('DB_SERVER')
DATABASE = 'heracles_db'
USERNAME = os.getenv('DB_USER')
PASSWORD = os.getenv('DB_PASS')

def get_db_connection():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        f'SERVER={SERVER};'
        f'DATABASE={DATABASE};'
        f'UID={USERNAME};'
        f'PWD={PASSWORD};'
        f'TrustServerCertificate=yes;'
    )
    return conn

def get_db_connection_dba():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        f'SERVER={SERVER};'
        f'DATABASE={DATABASE};'
        'UID=heracles_dba;'
        'PWD=DbaHeracles@2025;'
        f'TrustServerCertificate=yes;'
    )
    return conn

def dictfetchall(cursor):
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

def dictfetchone(cursor):
    row = cursor.fetchone()
    if row is None:
        return None
    columns = [column[0] for column in cursor.description]
    return dict(zip(columns, row))

# ==========================================
# MEMBER ROUTES
# ==========================================

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()

    # Fetch Active Subscription
    # joins users -> members -> memberships -> membership_plans
    cursor.execute("""
        SELECT TOP 1 mp.plan_name, ms.end_date, ms.status 
        FROM memberships ms
        JOIN membership_plans mp ON ms.plan_id = mp.plan_id
        JOIN members m ON ms.member_id = m.member_id
        WHERE m.user_id = ? AND ms.status = 'active'
        ORDER BY ms.end_date DESC
    """, (user_id,))
    active_plan = dictfetchone(cursor)

    # Fetch Recent Attendance
    cursor.execute("""
        SELECT TOP 5 a.check_in_time, a.check_out_time 
        FROM attendance a
        JOIN members m ON a.member_id = m.member_id
        WHERE m.user_id = ? 
        ORDER BY a.check_in_time DESC
    """, (user_id,))
    recent_attendance = dictfetchall(cursor)

    # Check if currently checked in
    cursor.execute("""
        SELECT a.attendance_id FROM attendance a
        JOIN members m ON a.member_id = m.member_id
        WHERE m.user_id = ? AND a.check_out_time IS NULL
    """, (user_id,))
    is_checked_in = cursor.fetchone() is not None

    cursor.close()
    db.close()

    return render_template('dashboard.html',
                           user=session['username'],
                           plan=active_plan,
                           attendance=recent_attendance,
                           is_checked_in=is_checked_in)

@app.route('/attendance/check-in', methods=['POST'])
def check_in():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor()
    # Get member_id from user_id
    cursor.execute("SELECT member_id FROM members WHERE user_id = ?", (session['user_id'],))
    member = cursor.fetchone()
    if member:
        cursor.execute("INSERT INTO attendance (member_id) VALUES (?)", (member[0],))
        db.commit()
    cursor.close()
    db.close()
    return redirect('/')

@app.route('/attendance/check-out', methods=['POST'])
def check_out():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE attendance SET check_out_time = GETDATE() 
        WHERE attendance_id = (
            SELECT TOP 1 a.attendance_id FROM attendance a
            JOIN members m ON a.member_id = m.member_id
            WHERE m.user_id = ? AND a.check_out_time IS NULL
        )
    """, (session['user_id'],))
    db.commit()
    cursor.close()
    db.close()
    return redirect('/')

# ==========================================
# AUTH ROUTES
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 1. Grab the username instead of email
        username = request.form['username']
        password = request.form['password']

        db = None
        cursor = None
        try:
            db = get_db_connection()
            cursor = db.cursor()

            # 2. Much simpler query! Just check the master users table directly
            cursor.execute("SELECT user_id, password_hash, role, username FROM users WHERE username = ?", (username,))
            user = dictfetchone(cursor)

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['user_id'] = user['user_id']
                session['username'] = user['username'] # Changed to store username
                session['role'] = user['role']

                if user['role'] == 'admin':
                    return redirect('/admin')
                else:
                    return redirect('/')
            else:
                return render_template('login.html', error="Invalid Username or Password")
        except pyodbc.Error as err:
            return f"Database Error: {err}"
        finally:
            if cursor:
                cursor.close()
            if db:
                db.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 1. Catch the new username from the form
        username = request.form['username']
        ic_number = request.form['ic_number']
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form.get('phone', 'N/A').strip() or 'N/A'
        date_of_birth = request.form.get('date_of_birth', '2000-01-01').strip() or '2000-01-01'
        emergency_contact = request.form.get('emergency_contact', 'N/A').strip() or 'N/A'
        emergency_phone = request.form.get('emergency_phone', 'N/A').strip() or 'N/A'
        password = request.form['password']

        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        db = None
        cursor = None
        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Insert into users table
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'member')",
                (username, hashed_pw)
            )

            cursor.execute("SELECT @@IDENTITY")
            user_id = int(cursor.fetchone()[0])

            # Insert into members table with all fields
            cursor.execute("""
                INSERT INTO members 
                    (user_id, full_name, ic_number, phone, email, 
                     date_of_birth, emergency_contact, emergency_phone, 
                     parq_cleared, medical_notes)
                VALUES 
                    (?, ?, ENCRYPTBYPASSPHRASE('Heracles@Secret2025', CAST(? AS VARCHAR(100))), 
                     ?, ?, ?, ?, ?, 0, NULL)
            """, (user_id, full_name, ic_number, phone, email, date_of_birth, emergency_contact, emergency_phone))

            db.commit()
            return redirect('/login')

        except pyodbc.Error as err:
            return f"Database Error: {err}"
        finally:
            if cursor:
                cursor.close()
            if db:
                db.close()

    return render_template('register.html')
# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "<h1>Unauthorized Access. Admins only.</h1>", 403

    db = get_db_connection()
    cursor = db.cursor()

    # Get all members with their plan info
    # Template expects: user_id, full_name, email, ic_number, created_at, plan_name, end_date
    cursor.execute("""
        SELECT 
            m.member_id as user_id,
            m.full_name,
            m.email,
            CONVERT(VARCHAR, DECRYPTBYPASSPHRASE('Heracles@Secret2025', m.ic_number)) as ic_number,
            u.created_at,
            mp.plan_name,
            ms.end_date
        FROM members m
        JOIN users u ON m.user_id = u.user_id
        LEFT JOIN memberships ms ON m.member_id = ms.member_id AND ms.status = 'active'
        LEFT JOIN membership_plans mp ON ms.plan_id = mp.plan_id
    """)
    members = dictfetchall(cursor)

    cursor.execute("SELECT * FROM membership_plans")
    plans = dictfetchall(cursor)

    cursor.close()
    db.close()

    return render_template('admin_dashboard.html', user=session['username'], members=members, plans=plans)

@app.route('/admin/create-plan', methods=['POST'])
def create_plan():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    plan_name = request.form['plan_name']
    description = request.form['description']
    price = request.form['price']
    duration_days = request.form['duration_days']

    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO membership_plans (plan_name, description, price, duration_days) VALUES (?, ?, ?, ?)",
            (plan_name, description, price, duration_days)
        )
        db.commit()
    except pyodbc.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/delete-plan/<int:plan_id>')
def delete_plan(plan_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("DELETE FROM membership_plans WHERE plan_id = ?", (plan_id,))
        db.commit()
    except pyodbc.Error as err:
        return f"<h1>Action Blocked</h1><p>Cannot delete a plan assigned to active members.</p><p>{err}</p>"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/assign-plan', methods=['POST'])
def assign_plan():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    # template sends user_id but it's actually member_id in our schema
    member_id = request.form['user_id']
    plan_id = request.form['plan_id']

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("SELECT duration_days FROM membership_plans WHERE plan_id = ?", (plan_id,))
        plan = dictfetchone(cursor)

        if plan:
            start_date = date.today()
            end_date = start_date + timedelta(days=plan['duration_days'])

            # Expire existing active memberships
            cursor.execute(
                "UPDATE memberships SET status = 'expired' WHERE member_id = ? AND status = 'active'",
                (member_id,)
            )

            # Insert new membership
            cursor.execute(
                "INSERT INTO memberships (member_id, plan_id, start_date, end_date, status) VALUES (?, ?, ?, ?, 'active')",
                (member_id, plan_id, start_date, end_date)
            )
            db.commit()

    except pyodbc.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/cancel-plan', methods=['POST'])
def cancel_plan():
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    member_id = request.form['user_id']

    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "UPDATE memberships SET status = 'expired' WHERE member_id = ? AND status = 'active'",
            (member_id,)
        )
        db.commit()
    except pyodbc.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/edit-member/<int:member_id>', methods=['GET', 'POST'])
def admin_edit_member(member_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    db = get_db_connection()
    cursor = db.cursor()

    if request.method == 'POST':
        new_name = request.form['full_name']
        new_email = request.form['email']
        new_ic = request.form['ic_number']
        new_phone = request.form.get('phone', 'N/A').strip() or 'N/A'
        new_dob = request.form.get('date_of_birth', '2000-01-01').strip() or '2000-01-01'
        new_emergency_contact = request.form.get('emergency_contact', 'N/A').strip() or 'N/A'
        new_emergency_phone = request.form.get('emergency_phone', 'N/A').strip() or 'N/A'
        parq_cleared = 1 if request.form.get('parq_cleared') else 0
        medical_notes = request.form.get('medical_notes', '').strip() or None

        try:
            cursor.execute("""
                UPDATE members 
                SET full_name = ?, email = ?, phone = ?,
                    date_of_birth = ?,
                    emergency_contact = ?, emergency_phone = ?,
                    ic_number = ENCRYPTBYPASSPHRASE('Heracles@Secret2025', CAST(? AS VARCHAR(100))),
                    parq_cleared = ?,
                    medical_notes = ?
                WHERE member_id = ?
            """, (new_name, new_email, new_phone, new_dob, new_emergency_contact, new_emergency_phone, new_ic, parq_cleared, medical_notes, member_id))
            db.commit()
        except pyodbc.Error as err:
            return f"Database Error: {err}"
        finally:
            cursor.close()
            db.close()

        return redirect('/admin')

    # GET - fetch member data using DBA connection to bypass Dynamic Data Masking
    db_dba = get_db_connection_dba()
    cursor_dba = db_dba.cursor()
    cursor_dba.execute("""
        SELECT 
            m.member_id as user_id,
            m.full_name,
            m.email,
            m.phone,
            m.date_of_birth,
            m.emergency_contact,
            m.emergency_phone,
            CONVERT(VARCHAR, DECRYPTBYPASSPHRASE('Heracles@Secret2025', m.ic_number)) as ic_number,
            m.parq_cleared,
            m.medical_notes
        FROM members m
        WHERE m.member_id = ?
    """, (member_id,))
    target_user = dictfetchone(cursor_dba)

    cursor_dba.close()
    db_dba.close()

    if not target_user:
        return "Member not found", 404

    return render_template('admin_edit_member.html', user=session['username'], target_user=target_user)

@app.route('/admin/member/<int:member_id>')
def admin_view_member(member_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    db = get_db_connection_dba()
    cursor = db.cursor()

    # Use DBA connection to bypass Dynamic Data Masking on email/phone fields
    cursor.execute("""
        SELECT 
            m.member_id as user_id,
            m.full_name,
            m.email,
            m.phone,
            m.date_of_birth,
            m.emergency_contact,
            m.emergency_phone,
            CONVERT(VARCHAR, DECRYPTBYPASSPHRASE('Heracles@Secret2025', m.ic_number)) as ic_number,
            m.parq_cleared,
            m.medical_notes,
            u.created_at
        FROM members m
        JOIN users u ON m.user_id = u.user_id
        WHERE m.member_id = ?
    """, (member_id,))
    target_user = dictfetchone(cursor)

    # template expects: sub.plan_name, sub.start_date, sub.end_date, sub.status
    cursor.execute("""
        SELECT mp.plan_name, ms.start_date, ms.end_date, ms.status 
        FROM memberships ms
        JOIN membership_plans mp ON ms.plan_id = mp.plan_id
        WHERE ms.member_id = ?
        ORDER BY ms.start_date DESC
    """, (member_id,))
    sub_history = dictfetchall(cursor)

    # template expects: session.check_in_time, session.check_out_time, session.duration_minutes
    cursor.execute("""
        SELECT check_in_time, check_out_time,
               DATEDIFF(MINUTE, check_in_time, ISNULL(check_out_time, GETDATE())) as duration_minutes
        FROM attendance
        WHERE member_id = ?
        ORDER BY check_in_time DESC
    """, (member_id,))
    session_history = dictfetchall(cursor)

    cursor.close()
    db.close()

    return render_template('admin_member_detail.html',
                           user=session['username'],
                           target_user=target_user,
                           sub_history=sub_history,
                           session_history=session_history)

@app.route('/admin/delete-member/<int:member_id>', methods=['POST'])
def admin_delete_member(member_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    try:
        db = get_db_connection()
        cursor = db.cursor()

        # Get user_id first
        cursor.execute("SELECT user_id FROM members WHERE member_id = ?", (member_id,))
        row = cursor.fetchone()
        if row:
            user_id = row[0]
            cursor.execute("DELETE FROM attendance WHERE member_id = ?", (member_id,))
            cursor.execute("DELETE FROM memberships WHERE member_id = ?", (member_id,))
            cursor.execute("DELETE FROM members WHERE member_id = ?", (member_id,))
            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            db.commit()

    except pyodbc.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

# ==========================================
# SUBSCRIPTION & SESSIONS ROUTES
# ==========================================

@app.route('/subscription')
def subscription_page():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor()

    # template expects: active_plan.plan_name, active_plan.description, 
    #                   active_plan.price, active_plan.start_date, active_plan.end_date
    cursor.execute("""
        SELECT TOP 1 mp.plan_name, mp.description, mp.price, ms.start_date, ms.end_date, ms.status 
        FROM memberships ms
        JOIN membership_plans mp ON ms.plan_id = mp.plan_id
        JOIN members m ON ms.member_id = m.member_id
        WHERE m.user_id = ? AND ms.status = 'active'
        ORDER BY ms.end_date DESC
    """, (session['user_id'],))
    active_plan = dictfetchone(cursor)

    # template expects: plan.plan_name, plan.start_date, plan.end_date
    cursor.execute("""
        SELECT mp.plan_name, ms.start_date, ms.end_date, ms.status 
        FROM memberships ms
        JOIN membership_plans mp ON ms.plan_id = mp.plan_id
        JOIN members m ON ms.member_id = m.member_id
        WHERE m.user_id = ? AND ms.status = 'expired'
        ORDER BY ms.end_date DESC
    """, (session['user_id'],))
    past_plans = dictfetchall(cursor)

    cursor.close()
    db.close()

    return render_template('subscription.html',
                           user=session['username'],
                           active_plan=active_plan,
                           past_plans=past_plans)

@app.route('/sessions')
def sessions_page():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor()

    # template expects: session.check_in_time, session.check_out_time, session.duration_minutes
    cursor.execute("""
        SELECT a.check_in_time, a.check_out_time,
               DATEDIFF(MINUTE, a.check_in_time, ISNULL(a.check_out_time, GETDATE())) as duration_minutes
        FROM attendance a
        JOIN members m ON a.member_id = m.member_id
        WHERE m.user_id = ?
        ORDER BY a.check_in_time DESC
    """, (session['user_id'],))
    all_sessions = dictfetchall(cursor)

    cursor.close()
    db.close()

    return render_template('sessions.html',
                           user=session['username'],
                           sessions=all_sessions)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    if request.method == 'POST':
        new_phone = request.form.get('phone', 'N/A').strip() or 'N/A'
        new_emergency_contact = request.form.get('emergency_contact', 'N/A').strip() or 'N/A'
        new_emergency_phone = request.form.get('emergency_phone', 'N/A').strip() or 'N/A'
        db = get_db_connection()
        cursor = db.cursor()
        try:
            cursor.execute("""
                UPDATE members SET phone = ?, emergency_contact = ?, emergency_phone = ?
                WHERE user_id = ?
            """, (new_phone, new_emergency_contact, new_emergency_phone, user_id))
            db.commit()
        except pyodbc.Error as err:
            return f"Database Error: {err}"
        finally:
            cursor.close()
            db.close()

        # Refetch updated profile using DBA connection for unmasked/decrypted data
        db_dba = get_db_connection_dba()
        cursor_dba = db_dba.cursor()
        cursor_dba.execute("""
            SELECT full_name, email, phone, emergency_contact, emergency_phone,
                   CONVERT(VARCHAR, DECRYPTBYPASSPHRASE('Heracles@Secret2025', ic_number)) as ic_number
            FROM members WHERE user_id = ?
        """, (user_id,))
        profile_data = dictfetchone(cursor_dba)
        cursor_dba.close()
        db_dba.close()
        return render_template('profile.html', user=session['username'], success="Profile updated!", profile=profile_data)

    # GET - fetch profile using DBA connection to get unmasked email and decrypted IC
    db_dba = get_db_connection_dba()
    cursor_dba = db_dba.cursor()
    cursor_dba.execute("""
        SELECT full_name, email, phone, emergency_contact, emergency_phone,
               CONVERT(VARCHAR, DECRYPTBYPASSPHRASE('Heracles@Secret2025', ic_number)) as ic_number
        FROM members WHERE user_id = ?
    """, (user_id,))
    profile_data = dictfetchone(cursor_dba)
    cursor_dba.close()
    db_dba.close()

    return render_template('profile.html', user=session['username'], profile=profile_data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Make sure the user is actually logged in
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # 1. Check if the new passwords match
        if new_password != confirm_password:
            return render_template('change_password.html', user=session['username'], error="New passwords do not match.")

        db = get_db_connection()
        cursor = db.cursor()

        try:
            # 2. Grab their current hash from the database
            cursor.execute("SELECT password_hash FROM users WHERE user_id = ?", (session['user_id'],))
            user_record = cursor.fetchone()

            # 3. Verify their old password is correct using bcrypt
            # Remember: bcrypt needs strings to be encoded into bytes first!
            if user_record and bcrypt.checkpw(current_password.encode('utf-8'), user_record[0].encode('utf-8')):
                
                # 4. Hash the new password and update the database
                new_hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hashed_pw, session['user_id']))
                db.commit()

                return render_template('change_password.html', user=session['username'], success="Password updated successfully!")
            else:
                return render_template('change_password.html', user=session['username'], error="Incorrect current password.")

        except pyodbc.Error as err:
            return f"Database Error: {err}"
        finally:
            cursor.close()
            db.close()

    # If it's a GET request, just show the blank form
    return render_template('change_password.html', user=session['username'])


if __name__ == '__main__':
    app.run(debug=True, port=8000)