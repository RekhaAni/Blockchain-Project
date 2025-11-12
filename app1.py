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
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile_number TEXT NOT NULL UNIQUE,
            government_proof_type TEXT NOT NULL,
            government_proof_id TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (government_proof_id, mobile_number)
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

    # Create sell_alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sell_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_number TEXT NOT NULL,
            seller TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create ownership_transfer_requests table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ownership_transfer_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_number TEXT NOT NULL,
            current_owner TEXT NOT NULL,
            new_owner TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            INSERT INTO users (first_name, last_name, mobile_number, government_proof_type, government_proof_id, username, password, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ("Admin", "User", "9876543210", "Aadhar Card", "ADMIN123456789", "admin", hashed_password, "admin"))
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

# User Registration (Public)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        mobile_number = request.form["mobile_number"]
        government_proof_type = request.form["government_proof_type"]
        government_proof_id = request.form["government_proof_id"]
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (first_name, last_name, mobile_number, government_proof_type, government_proof_id, username, password, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, mobile_number, government_proof_type, government_proof_id, username, hashed_password, "public"))
            conn.commit()
            flash("User registered successfully.")
            return redirect(url_for("public_login"))
        except sqlite3.IntegrityError:
            flash("Username, Mobile Number, or Government Proof ID already exists!")
        conn.close()
    return render_template("public/public_public_register.html")

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

# Seller List Property for Sale
@app.route("/seller/list-property", methods=["GET", "POST"])
def seller_list_property():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        survey_number = request.form["survey_number"]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the survey number exists and belongs to the seller
        cursor.execute("SELECT * FROM land_records WHERE survey_number = ? AND owner = ?", (survey_number, session["username"]))
        record = cursor.fetchone()

        if not record:
            flash("You do not own this property.")
            conn.close()
            return redirect(url_for("seller_list_property"))

        # Insert the sell alert
        try:
            cursor.execute("""
                INSERT INTO sell_alerts (survey_number, seller)
                VALUES (?, ?)
            """, (survey_number, session["username"]))
            conn.commit()
            flash("Property listed for sale successfully.")
        except sqlite3.IntegrityError:
            flash("This property is already listed for sale.")
        conn.close()
        return redirect(url_for("public_dashboard"))

    return render_template("seller/list_property.html")

# Buyer View Selling Lands
@app.route("/buyer/view-selling-lands")
def buyer_view_selling_lands():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM sell_alerts WHERE status = 'active'
    """)
    selling_lands = cursor.fetchall()
    conn.close()
    return render_template("buyer/view_selling_lands.html", selling_lands=selling_lands)

# Buyer Request to Buy Land
@app.route("/buyer/request-buy/<string:survey_number>", methods=["POST"])
def buyer_request_buy(survey_number):
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the survey number exists in sell alerts
    cursor.execute("SELECT * FROM sell_alerts WHERE survey_number = ? AND status = 'active'", (survey_number,))
    sell_alert = cursor.fetchone()

    if not sell_alert:
        flash("This property is not available for sale.")
        conn.close()
        return redirect(url_for("buyer_view_selling_lands"))

    # Insert the ownership transfer request
    try:
        cursor.execute("""
            INSERT INTO ownership_transfer_requests (survey_number, current_owner, new_owner)
            VALUES (?, ?, ?)
        """, (survey_number, sell_alert["seller"], session["username"]))
        conn.commit()
        flash("Buy request submitted successfully.")

        # Update the sell alert status to inactive
        cursor.execute("""
            UPDATE sell_alerts
            SET status = 'inactive'
            WHERE survey_number = ?
        """, (survey_number,))
        conn.commit()
    except sqlite3.IntegrityError:
        flash("Buy request already exists for this property.")
    conn.close()
    return redirect(url_for("public_dashboard"))

# Officer Approve Ownership Transfer
@app.route("/officer/approve-transfer/<int:request_id>", methods=["POST"])
def approve_transfer(request_id):
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the transfer request
    cursor.execute("SELECT * FROM ownership_transfer_requests WHERE id = ?", (request_id,))
    transfer_request = cursor.fetchone()

    if not transfer_request or transfer_request["status"] != "pending":
        flash("Invalid or already processed transfer request.")
        conn.close()
        return redirect(url_for("officer_dashboard"))

    # Update the land record with the new owner
    cursor.execute("""
        UPDATE land_records
        SET owner = ?
        WHERE survey_number = ?
    """, (transfer_request["new_owner"], transfer_request["survey_number"]))

    # Mark the transfer request as approved
    cursor.execute("""
        UPDATE ownership_transfer_requests
        SET status = 'approved'
        WHERE id = ?
    """, (request_id,))

    conn.commit()
    conn.close()
    flash("Ownership transfer approved successfully.")
    return redirect(url_for("officer_dashboard"))

# Public Dashboard
@app.route("/public/dashboard")
def public_dashboard():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    return render_template("public/dashboard.html")

if __name__ == "__main__":
    init_db()  # Initialize the database
    create_default_admin()  # Create default admin account
    app.run(debug=True)