from flask import Flask, render_template, request, redirect, url_for, session
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


# home page route (Placeholder for now)
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
    
    return render_template('dashboard.html', user=session['email'])

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
            session['user_id'] = user['user_id']
            session['email'] = user['email']
            session['role'] = user['role']
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

    # Fetch all members to display
    cursor.execute("SELECT user_id, ic_number, full_name, email, created_at FROM users WHERE role = 'member'")
    members = cursor.fetchall()

    # Fetch all membership plans
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

# logout route
@app.route('/logout')
def logout():
     session.clear()
     return redirect('/login')   


if __name__ == '__main__':
        app.run(debug=True, port=8000)

