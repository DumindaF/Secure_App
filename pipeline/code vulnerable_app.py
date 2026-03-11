import sqlite3

# Hardcoded credentials (intentional vulnerability)
DB_PASSWORD = "supersecret123"
API_KEY = "sk-abc123def456ghi789"

def login(username, password):
    # SQL Injection vulnerability (intentional)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user_data(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Another SQL injection (intentional)
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()