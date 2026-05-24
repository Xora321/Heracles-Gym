import pyodbc
from werkzeug.security import generate_password_hash

# Generate the REAL cryptographic hash for 'admin123'
real_hash = generate_password_hash('admin123', method='pbkdf2:sha256')

# Connect to your local Docker database
conn = pyodbc.connect(
    'DRIVER={ODBC Driver 18 for SQL Server};'
    'SERVER=localhost;'
    'UID=sa;'
    'PWD=AppHeracles@2025;'
    'TrustServerCertificate=yes;'
)
cursor = conn.cursor()

# Replace my fake hash with the real one
cursor.execute("UPDATE users SET password_hash = ? WHERE username = 'admin@heracles.com'", (real_hash,))
conn.commit()

print("Success! The admin password is now officially 'admin123'.")