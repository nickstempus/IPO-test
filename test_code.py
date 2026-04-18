import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials (sensitive data exposure)
DB_PATH = "users.db"
ADMIN_PASSWORD = "admin123"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # SQL Injection vulnerability (string concatenation)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"


@app.route("/exec", methods=["GET"])
def exec_command():
    cmd = request.args.get("cmd")

    # Command Injection vulnerability
    output = os.popen(cmd).read()
    return output


@app.route("/readfile", methods=["GET"])
def read_file():
    filename = request.args.get("file")

    # Path Traversal vulnerability
    with open(filename, "r") as f:
        return f.read()


@app.route("/admin", methods=["GET"])
def admin():
    password = request.args.get("password")

    # Weak authentication check
    if password == ADMIN_PASSWORD:
        return "Welcome admin"
    return "Access denied"


if __name__ == "__main__":
    # Debug mode enabled (information disclosure risk)
    app.run(debug=True)