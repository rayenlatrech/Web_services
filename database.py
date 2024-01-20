import sqlite3

# Connect to SQLite database (or create if it doesn't exist)
conn = sqlite3.connect('user_data.db')
cursor = conn.cursor()

# Create 'users' table to store user information
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    portfolio TEXT,
                    transactions TEXT
                )''')



conn.commit()
conn.close()

print("Database 'user_data.db' created successfully.")
