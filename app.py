from flask import Flask, render_template, request, redirect, url_for, session
from datetime import date, timedelta
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "secret_gym_key"

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="database123", 
        database="heracles_gym"
    )


# ==========================================
# MEMBER ROUTES
# ==========================================

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # 1. Fetch Active Subscription (JOIN with plans table to get the name)
    cursor.execute("""
        SELECT mp.plan_name, s.end_date, s.status 
        FROM subscriptions s
        JOIN membership_plans mp ON s.plan_id = mp.plan_id
        WHERE s.user_id = %s AND s.status = 'active'
        ORDER BY s.end_date DESC LIMIT 1
    """, (user_id,))
    active_plan = cursor.fetchone()

    # 2. Fetch Recent Attendance History
    cursor.execute("""
        SELECT check_in_time, check_out_time 
        FROM attendance 
        WHERE user_id = %s 
        ORDER BY check_in_time DESC LIMIT 5
    """, (user_id,))
    recent_attendance = cursor.fetchall()

    # 3. Check if currently checked in (has an active check-in but no check-out)
    cursor.execute("SELECT record_id FROM attendance WHERE user_id = %s AND check_out_time IS NULL", (user_id,))
    is_checked_in = cursor.fetchone() is not None

    cursor.close()
    db.close()

    return render_template('dashboard.html', 
                           user=session['email'],
                           plan=active_plan,
                           attendance=recent_attendance,
                           is_checked_in=is_checked_in)

@app.route('/attendance/check-in', methods=['POST'])
def check_in():
    if 'user_id' not in session: return redirect('/login')
    
    db = get_db_connection()
    cursor = db.cursor()
    # SQL INSERT for new attendance record
    cursor.execute("INSERT INTO attendance (user_id, check_in_time) VALUES (%s, NOW())", (session['user_id'],))
    db.commit()
    cursor.close()
    db.close()
    return redirect('/')

@app.route('/attendance/check-out', methods=['POST'])
def check_out():
    if 'user_id' not in session: return redirect('/login')
    
    db = get_db_connection()
    cursor = db.cursor()
    # SQL UPDATE to close the attendance record
    cursor.execute("UPDATE attendance SET check_out_time = NOW() WHERE user_id = %s AND check_out_time IS NULL", (session['user_id'],))
    db.commit()
    cursor.close()
    db.close()
    return redirect('/')

# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()

        if user and check_password_hash(user['password_hash'], password):
            # 1. Set the session variables
            session['user_id'] = user['user_id']
            session['email'] = user['email']
            session['role'] = user['role']
            
            # 2. Redirect based on the user's role
            if user['role'] == 'admin':
                return redirect('/admin')
            else:
                return redirect('/')
        else:
            return render_template('login.html', error="Invalid Email or Password")
            
    return render_template('login.html')

# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ic_number = request.form['ic_number']
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        
        # Security Measure: Never store raw passwords
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            db = get_db_connection()
            cursor = db.cursor()
            
            sql = "INSERT INTO users (ic_number, full_name, email, password_hash, role) VALUES (%s, %s, %s, %s, %s)"
            val = (ic_number, full_name, email, hashed_pw, 'member')
            
            cursor.execute(sql, val)
            db.commit()
            
            return redirect('/login')
        except mysql.connector.Error as err:
            return f"Database Error: {err}"
        finally:
            cursor.close()
            db.close()
            
    return render_template('register.html')

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route('/admin')
def admin_dashboard():
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "<h1>Unauthorized Access. Admins only.</h1>", 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Fetch all members to display ALONG with their active subscription details
    cursor.execute("""
        SELECT u.user_id, u.ic_number, u.full_name, u.email, u.created_at, 
               mp.plan_name, s.end_date 
        FROM users u
        LEFT JOIN subscriptions s ON u.user_id = s.user_id AND s.status = 'active'
        LEFT JOIN membership_plans mp ON s.plan_id = mp.plan_id
        WHERE u.role = 'member'
    """)
    members = cursor.fetchall()

    # Fetch all membership plans for the dropdown menu
    cursor.execute("SELECT * FROM membership_plans")
    plans = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('admin_dashboard.html', user=session['email'], members=members, plans=plans)

@app.route('/admin/create-plan', methods=['POST'])
def create_plan():
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    plan_name = request.form['plan_name']
    description = request.form['description']
    price = request.form['price']
    duration_days = request.form['duration_days']

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Parameterized query to prevent SQL injection
        sql = "INSERT INTO membership_plans (plan_name, description, price, duration_days) VALUES (%s, %s, %s, %s)"
        val = (plan_name, description, price, duration_days)
        
        cursor.execute(sql, val)
        db.commit()
    except mysql.connector.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/delete-plan/<int:plan_id>')
def delete_plan(plan_id):
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # SQL DELETE command
        cursor.execute("DELETE FROM membership_plans WHERE plan_id = %s", (plan_id,))
        db.commit()
        
    except mysql.connector.Error as err:
        return f"<h1>Action Blocked</h1><p>You cannot delete a plan that is currently assigned to active users. Please assign those users to a new plan first.</p><p>Database Error: {err}</p>"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/assign-plan', methods=['POST'])
def assign_plan():
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    user_id = request.form['user_id']
    plan_id = request.form['plan_id']

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # 1. Get the duration of the selected plan
        cursor.execute("SELECT duration_days FROM membership_plans WHERE plan_id = %s", (plan_id,))
        plan = cursor.fetchone()
        
        if plan:
            # 2. Calculate dates
            start_date = date.today()
            end_date = start_date + timedelta(days=plan['duration_days'])
            
            # 3. Deactivate any old plans this user had
            cursor.execute("UPDATE subscriptions SET status = 'expired' WHERE user_id = %s", (user_id,))
            
            # 4. Insert the new active subscription
            sql = "INSERT INTO subscriptions (user_id, plan_id, start_date, end_date, status) VALUES (%s, %s, %s, %s, 'active')"
            cursor.execute(sql, (user_id, plan_id, start_date, end_date))
            db.commit()

    except mysql.connector.Error as err:
        return f"Database Error: {err}"
    finally:

        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/cancel-plan', methods=['POST'])
def cancel_plan():
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    user_id = request.form['user_id']

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Immediately expire any currently active subscription for this user
        cursor.execute("UPDATE subscriptions SET status = 'expired' WHERE user_id = %s AND status = 'active'", (user_id,))
        db.commit()

    except mysql.connector.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/admin/member/<int:target_user_id>')
def admin_view_member(target_user_id):
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # 1. Get user info
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (target_user_id,))
    target_user = cursor.fetchone()

    # 2. Get their full subscription history
    cursor.execute("""
        SELECT mp.plan_name, s.start_date, s.end_date, s.status 
        FROM subscriptions s
        JOIN membership_plans mp ON s.plan_id = mp.plan_id
        WHERE s.user_id = %s
        ORDER BY s.start_date DESC
    """, (target_user_id,))
    sub_history = cursor.fetchall()

    # 3. Get their full attendance history
    cursor.execute("""
        SELECT check_in_time, check_out_time, 
               TIMESTAMPDIFF(MINUTE, check_in_time, IFNULL(check_out_time, NOW())) as duration_minutes
        FROM attendance 
        WHERE user_id = %s 
        ORDER BY check_in_time DESC
    """, (target_user_id,))
    session_history = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('admin_member_detail.html', 
                           user=session['email'], 
                           target_user=target_user,
                           sub_history=sub_history,
                           session_history=session_history)

@app.route('/admin/edit-member/<int:target_user_id>', methods=['GET', 'POST'])
def admin_edit_member(target_user_id):
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # If the admin submits the updated form
    if request.method == 'POST':
        new_name = request.form['full_name']
        new_email = request.form['email']
        new_ic = request.form['ic_number']
        
        try:
            cursor.execute("""
                UPDATE users 
                SET full_name = %s, email = %s, ic_number = %s 
                WHERE user_id = %s
            """, (new_name, new_email, new_ic, target_user_id))
            db.commit()
        except mysql.connector.Error as err:
            return f"Database Error: {err}"
        finally:
            cursor.close()
            db.close()
        
        return redirect('/admin')
    
    # If the admin is just loading the page, fetch the user data to pre-fill the form
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (target_user_id,))
    target_user = cursor.fetchone()
    
    cursor.close()
    db.close()

    if not target_user:
        return "User not found", 404

    return render_template('admin_edit_member.html', user=session['email'], target_user=target_user)

@app.route('/admin/delete-member/<int:target_user_id>', methods=['POST'])
def admin_delete_member(target_user_id):
    # Security: Strict Admin Check
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Unauthorized Access", 403

    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # PDPA Compliance: We must delete all their foreign key records first before deleting the user
        cursor.execute("DELETE FROM attendance WHERE user_id = %s", (target_user_id,))
        cursor.execute("DELETE FROM subscriptions WHERE user_id = %s", (target_user_id,))
        
        # Finally, delete their personal data profile
        cursor.execute("DELETE FROM users WHERE user_id = %s", (target_user_id,))
        db.commit()

    except mysql.connector.Error as err:
        return f"Database Error: {err}"
    finally:
        cursor.close()
        db.close()

    return redirect('/admin')

@app.route('/subscription')
def subscription_page():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # 1. Fetch current active subscription with full details
    cursor.execute("""
        SELECT mp.plan_name, mp.description, mp.price, s.start_date, s.end_date, s.status 
        FROM subscriptions s
        JOIN membership_plans mp ON s.plan_id = mp.plan_id
        WHERE s.user_id = %s AND s.status = 'active'
        ORDER BY s.end_date DESC LIMIT 1
    """, (session['user_id'],))
    active_plan = cursor.fetchone()

    # 2. Fetch past (expired) subscriptions
    cursor.execute("""
        SELECT mp.plan_name, s.start_date, s.end_date, s.status 
        FROM subscriptions s
        JOIN membership_plans mp ON s.plan_id = mp.plan_id
        WHERE s.user_id = %s AND s.status = 'expired'
        ORDER BY s.end_date DESC
    """, (session['user_id'],))
    past_plans = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('subscription.html', 
                           user=session['email'],
                           active_plan=active_plan,
                           past_plans=past_plans)

@app.route('/sessions')
def sessions_page():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Fetch all attendance records for this user, calculating the duration in minutes
    cursor.execute("""
        SELECT check_in_time, check_out_time, 
               TIMESTAMPDIFF(MINUTE, check_in_time, IFNULL(check_out_time, NOW())) as duration_minutes
        FROM attendance 
        WHERE user_id = %s 
        ORDER BY check_in_time DESC
    """, (session['user_id'],))
    all_sessions = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template('sessions.html', 
                           user=session['email'],
                           sessions=all_sessions)

# logout route
@app.route('/logout')
def logout():
     session.clear()
     return redirect('/login')   


if __name__ == '__main__':
        app.run(debug=True, port=8000)

