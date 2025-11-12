from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database configuration
DATABASE = "land_records.db"

# Get database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access rows as dictionaries
    return conn

# Initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            photo TEXT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            address TEXT,
            aadhar_card TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create land_records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS land_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_number TEXT NOT NULL UNIQUE,
            owner TEXT NOT NULL,
            location TEXT NOT NULL,
            officer_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (officer_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

# Create default admin account if not exists
def create_default_admin():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()

    if not admin:
        hashed_password = generate_password_hash("admin123", method="pbkdf2:sha256")
        cursor.execute("""
            INSERT INTO users (photo, username, password, role, address, aadhar_card)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("default.jpg", "admin", hashed_password, "admin", "Admin Address", "1234-5678-9012"))
        conn.commit()
    conn.close()

# Generate CAPTCHA
def generate_captcha():
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session["captcha"] = captcha
    return captcha

# Home route
@app.route("/")
def home():
    return render_template("Home.html")

# Admin Registration
@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        aadhar_card = request.form["aadhar_card"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (photo, username, password, role, address, aadhar_card)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("default.jpg", username, hashed_password, "admin", address, aadhar_card))
            conn.commit()
            flash("Admin registered successfully.")
            return redirect(url_for("admin_login"))
        except sqlite3.IntegrityError:
            flash("Username already exists!")
        conn.close()

    return render_template("admin/admin_register.html")

# Admin Login
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        captcha = request.form["captcha"]

        if captcha != session.get("captcha"):
            flash("Invalid CAPTCHA!")
            return redirect(url_for("admin_login"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password) and user["role"] == "admin":
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Login successful as Admin.")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid credentials or unauthorized role!")

    return render_template("admin/admin_login.html", captcha=generate_captcha())

# Officer Registration (Admin-only)
@app.route("/officer/register", methods=["GET", "POST"])
def officer_register():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        aadhar_card = request.form["aadhar_card"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (photo, username, password, role, address, aadhar_card)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("default.jpg", username, hashed_password, "officer", address, aadhar_card))
            conn.commit()
            flash("Officer registered successfully.")
            return redirect(url_for("manage_officers"))
        except sqlite3.IntegrityError:
            flash("Username already exists!")
        conn.close()

    return render_template("officer/officer_register.html")

# Officer Login
@app.route("/officer/login", methods=["GET", "POST"])
def officer_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        captcha = request.form["captcha"]

        if captcha != session.get("captcha"):
            flash("Invalid CAPTCHA!")
            return redirect(url_for("officer_login"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password) and user["role"] == "officer":
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Login successful as Officer.")
            return redirect(url_for("officer_dashboard"))
        else:
            flash("Invalid credentials or unauthorized role!")

    return render_template("officer/officer_login.html", captcha=generate_captcha())

# Public Registration
@app.route("/public/register", methods=["GET", "POST"])
def public_register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        aadhar_card = request.form["aadhar_card"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (photo, username, password, role, address, aadhar_card)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("default.jpg", username, hashed_password, "public", address, aadhar_card))
            conn.commit()
            flash("Public user registered successfully.")
            return redirect(url_for("public_login"))
        except sqlite3.IntegrityError:
            flash("Username already exists!")
        conn.close()

    return render_template("public/public_register.html")

# Public Login
@app.route("/public/login", methods=["GET", "POST"])
def public_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        captcha = request.form["captcha"]

        if captcha != session.get("captcha"):
            flash("Invalid CAPTCHA!")
            return redirect(url_for("public_login"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password) and user["role"] == "public":
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Login successful as Public User.")
            return redirect(url_for("public_dashboard"))
        else:
            flash("Invalid credentials or unauthorized role!")

    return render_template("public/login.html", captcha=generate_captcha())

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))

# Admin Dashboard
@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    return render_template("admin/dashboard.html")

# Manage Officers
@app.route("/admin/manage-officers", methods=["GET", "POST"])
def manage_officers():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        # Add new officer
        photo = request.form["photo"]
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        aadhar_card = request.form["aadhar_card"]
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        try:
            cursor.execute("""
                INSERT INTO users (photo, username, password, role, address, aadhar_card)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (photo, username, hashed_password, "officer", address, aadhar_card))
            conn.commit()
            flash("Officer added successfully.")
        except sqlite3.IntegrityError:
            flash("Username already exists!")

    # Fetch all officers
    cursor.execute("SELECT * FROM users WHERE role = 'officer'")
    officers = cursor.fetchall()
    conn.close()
    return render_template("admin/manage_officers.html", officers=officers)

# Delete Officer
@app.route("/admin/delete-officer/<int:officer_id>", methods=["POST"])
def delete_officer(officer_id):
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (officer_id,))
    conn.commit()
    conn.close()
    flash("Officer deleted successfully.")
    return redirect(url_for("manage_officers"))

# Monitor Records
@app.route("/admin/monitor-records")
def monitor_records():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT lr.*, u.username AS officer_name
        FROM land_records lr
        JOIN users u ON lr.officer_id = u.id
    """)
    records = cursor.fetchall()
    conn.close()
    return render_template("admin/monitor_records.html", records=records)

# Officer Dashboard
@app.route("/officer/dashboard")
def officer_dashboard():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    return render_template("officer/dashboard.html")

# Add Land Record (Officer Only)
@app.route("/add-record", methods=["GET", "POST"])
def add_record():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        survey_number = request.form["survey_number"]
        owner = request.form["owner"]
        location = request.form["location"]

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO land_records (survey_number, owner, location, officer_id)
                VALUES (?, ?, ?, ?)
            """, (survey_number, owner, location, session["user_id"]))
            conn.commit()
            flash("Land record added successfully.")
        except sqlite3.IntegrityError:
            flash("Survey number already exists!")
        conn.close()
        return redirect(url_for("officer_dashboard"))
    return render_template("add_record.html")

# Public Dashboard
@app.route("/public/dashboard")
def public_dashboard():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    return render_template("public/dashboard.html")

# View Land Record
@app.route("/view-record", methods=["GET", "POST"])
def view_record():
    if request.method == "POST":
        survey_number = request.form["survey_number"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM land_records WHERE survey_number = ?", (survey_number,))
        record = cursor.fetchone()
        conn.close()

        if record:
            return render_template("view_record.html", record=record)
        else:
            flash("Record not found.")
    return render_template("view_record.html", record=None)

if __name__ == "__main__":
    init_db()  # Initialize the database
    create_default_admin()  # Create default admin account
    app.run(debug=True)