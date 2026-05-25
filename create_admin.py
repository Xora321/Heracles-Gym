import pyodbc
import os
import bcrypt
from dotenv import load_dotenv

# Load your connection settings from the .env file
load_dotenv()

SERVER = os.getenv('DB_SERVER')
DATABASE = 'heracles_db'
USERNAME = os.getenv('DB_USER')
PASSWORD = os.getenv('DB_PASS')

admin_email = 'masteradmin@heracles.com'
raw_password = 'admin123'
admin_name = 'New Administrator'
staff_id = 'ADM-999' # Added to satisfy your friend's database rule!

# 1. Generate the proper Bcrypt Hash
salt = bcrypt.gensalt()
hashed_pw = bcrypt.hashpw(raw_password.encode('utf-8'), salt).decode('utf-8')

# 2. Connect to the database
conn = pyodbc.connect(
    'DRIVER={ODBC Driver 18 for SQL Server};'
    f'SERVER={SERVER};'
    f'DATABASE={DATABASE};'
    f'UID={USERNAME};'
    f'PWD={PASSWORD};'
    f'TrustServerCertificate=yes;'
)
cursor = conn.cursor()

try:
    # 3. Insert into the users table
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        (admin_email, hashed_pw)
    )
    
    # 4. Get the new user_id
    cursor.execute("SELECT @@IDENTITY")
    new_user_id = int(cursor.fetchone()[0])
    
    # 5. Insert into the admins table (Now including staff_id!)
    cursor.execute(
        "INSERT INTO admins (user_id, full_name, staff_id) VALUES (?, ?, ?)",
        (new_user_id, admin_name, staff_id)
    )
    
    conn.commit()
    print(f"Success! New admin created.\nEmail: {admin_email}\nPassword: {raw_password}")

except pyodbc.Error as e:
    print(f"Database Error: {e}")
finally:
    cursor.close()
    conn.close()