import json
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

from blockchain.blockchain import Blockchain
from blockchain.smart_contract import SmartContract

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
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create admins table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile_number TEXT NOT NULL UNIQUE,
            government_proof_type TEXT NOT NULL,
            government_proof_id TEXT NOT NULL,
            address TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Create officers table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS officers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile_number TEXT NOT NULL UNIQUE,
            government_proof_type TEXT NOT NULL,
            government_proof_id TEXT NOT NULL,
            address TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Create public_users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS public_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            mobile_number TEXT NOT NULL UNIQUE,
            government_proof_type TEXT NOT NULL,
            government_proof_id TEXT NOT NULL,
            address TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Create land_records table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS land_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_number TEXT NOT NULL UNIQUE,
            kahata TEXT,
            owner_name TEXT NOT NULL,
            father_name TEXT,
            village TEXT NOT NULL,
            address TEXT NOT NULL,
            property_size REAL NOT NULL,
            size_unit TEXT NOT NULL, -- 'square_feet' or 'acres'
            crop_details TEXT,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (survey_number) REFERENCES land_records(survey_number)
    )
    """)

    # Create ownership_transfer_requests table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ownership_transfer_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            survey_number TEXT NOT NULL,
            current_owner TEXT NOT NULL,
            new_owner TEXT NOT NULL,
            request_type TEXT NOT NULL, -- 'sell' or 'transfer'
            status TEXT DEFAULT 'pending', -- 'pending', 'approved', or 'rejected'
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
            INSERT INTO users (username, password, role)
            VALUES (?, ?, ?)
        """, ("admin", hashed_password, "admin"))
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
        # Collect form data
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        mobile_number = request.form["mobile_number"]
        government_proof_type = request.form["government_proof_type"]
        government_proof_id = request.form["government_proof_id"]
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Insert into users table
            cursor.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (username, hashed_password, "public"))
            user_id = cursor.lastrowid  # Get the ID of the newly inserted user

            # Insert into public_users table
            cursor.execute("""
                INSERT INTO public_users (user_id, first_name, last_name, mobile_number, government_proof_type, government_proof_id, address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, first_name, last_name, mobile_number, government_proof_type, government_proof_id, address))

            conn.commit()
            flash("User registered successfully.")
            return redirect(url_for("public_login"))
        except sqlite3.IntegrityError:
            flash("Username, Mobile Number, or Government Proof ID already exists!")
        finally:
            conn.close()

    return render_template("public/public_register.html")

@app.route("/login", methods=["GET"])
def login():
    # Get the role from the query string
    role = request.args.get("role")

    # Validate the role against allowed roles
    allowed_roles = ["admin", "officer", "public"]
    if role in allowed_roles:
        # Redirect to the appropriate login page
        return redirect(url_for(f"{role}_login"))
    else:
        # Handle invalid or missing role
        flash("Invalid role specified. Please select a valid role.")
        return redirect(url_for("home"))

@app.route("/officer/login", methods=["GET", "POST"])
def officer_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        captcha = request.form["captcha"]

        # Validate CAPTCHA
        if captcha != session.get("captcha"):
            flash("Invalid CAPTCHA!")
            return redirect(url_for("officer_login"))

        # Fetch user from database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # Validate credentials and role
        if user and check_password_hash(user["password"], password) and user["role"] == "officer":
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Login successful as Officer.")
            return redirect(url_for("officer_dashboard"))
        else:
            flash("Invalid credentials or unauthorized role!")

    # Render login page with CAPTCHA
    return render_template("officer/officer_login.html", captcha=generate_captcha())

@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
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
            """, (first_name, last_name, mobile_number, government_proof_type, government_proof_id, username, hashed_password, "admin"))
            conn.commit()
            flash("Admin registered successfully.")
            return redirect(url_for("admin_login"))
        except sqlite3.IntegrityError:
            flash("Username, Mobile Number, or Government Proof ID already exists!")
        conn.close()
    return render_template("admin/admin_register.html")

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


@app.route("/officer/register", methods=["GET", "POST"])
def officer_register():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        # Collect form data
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        mobile_number = request.form["mobile_number"]
        government_proof_type = request.form["government_proof_type"]
        government_proof_id = request.form["government_proof_id"]
        address = request.form["address"]
        username = request.form["username"]
        password = request.form["password"]

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Insert into users table
            cursor.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (username, hashed_password, "officer"))
            user_id = cursor.lastrowid  # Get the ID of the newly inserted user

            # Insert into officers table
            cursor.execute("""
                INSERT INTO officers (user_id, first_name, last_name, mobile_number, government_proof_type, government_proof_id, address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, first_name, last_name, mobile_number, government_proof_type, government_proof_id, address))
            conn.commit()
            flash("Officer registered successfully.")
            return redirect(url_for("manage_officers"))
        except sqlite3.IntegrityError:
            flash("Username, Mobile Number, or Government Proof ID already exists!")
        finally:
            conn.close()

    return render_template("officer/officer_register.html")

@app.route("/officer/dashboard")
def officer_dashboard():
    # Ensure only officers can access this route
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    # Fetch pending ownership transfer requests
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests
        WHERE status = 'pending'
    """)
    pending_transfers = cursor.fetchall()

    # Close the database connection
    conn.close()

    # Render the officer dashboard template with pending transfers
    return render_template(
        "officer/dashboard.html",
        pending_transfers=pending_transfers,
        pending_transfers_count=len(pending_transfers)
    )

@app.route("/public/register", methods=["GET", "POST"])
def public_register():
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
            flash("Public user registered successfully.")
            return redirect(url_for("public_login"))
        except sqlite3.IntegrityError:
            flash("Username, Mobile Number, or Government Proof ID already exists!")
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

# Update Officer
@app.route("/admin/update-officer/<int:officer_id>", methods=["GET", "POST"])
def update_officer(officer_id):
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        mobile_number = request.form["mobile_number"]
        government_proof_type = request.form["government_proof_type"]
        government_proof_id = request.form["government_proof_id"]
        username = request.form["username"]
        cursor.execute("""
            UPDATE users
            SET first_name = ?, last_name = ?, mobile_number = ?, government_proof_type = ?, government_proof_id = ?, username = ?
            WHERE id = ?
        """, (first_name, last_name, mobile_number, government_proof_type, government_proof_id, username, officer_id))
        conn.commit()
        flash("Officer updated successfully.")
        conn.close()
        return redirect(url_for("admin_dashboard"))
    # Fetch officer details
    cursor.execute("SELECT * FROM users WHERE id = ?", (officer_id,))
    officer = cursor.fetchone()
    conn.close()
    return render_template("admin/update_officer.html", officer=officer)


# Delete Officer
@app.route("/admin/delete-officer/<int:officer_id>", methods=["POST"])
def delete_officer(officer_id):
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete the officer by ID
    cursor.execute("DELETE FROM users WHERE id = ? AND role = 'officer'", (officer_id,))
    conn.commit()
    conn.close()

    flash("Officer deleted successfully.")
    return redirect(url_for("manage_officers"))

# Seller List Property for Sale
@app.route("/seller/list-property", methods=["POST"])
def seller_list_property():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    survey_number = request.form["survey_number"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the survey number exists and belongs to the seller
    cursor.execute("""
        SELECT * FROM land_records WHERE survey_number = ? AND owner_name = ?
    """, (survey_number, session["username"]))
    record = cursor.fetchone()

    if not record:
        flash("You do not own this property.")
        conn.close()
        return redirect(url_for("public_dashboard"))

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

@app.route("/seller/list-property-for-sale", methods=["GET", "POST"])
def seller_list_property_for_sale():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        survey_number = request.form["survey_number"]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the survey number exists and belongs to the seller
        cursor.execute("""
            SELECT * FROM land_records WHERE survey_number = ? AND owner_name = ?
        """, (survey_number, session["username"]))
        record = cursor.fetchone()

        if not record:
            flash("You do not own this property.")
            conn.close()
            return redirect(url_for("seller_list_property_for_sale"))

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

    return render_template("seller/list_property_for_sale.html")

@app.route("/officer/view-pending-transfers")
def view_pending_transfers():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all pending ownership transfer requests
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests
        WHERE status = 'pending'
    """)
    pending_transfers = cursor.fetchall()
    conn.close()

    return render_template("officer/view_pending_transfers.html", pending_transfers=pending_transfers)


@app.route("/officer/view-all-records")
def view_all_records():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all land records
    cursor.execute("""
        SELECT * FROM land_records
    """)
    records = cursor.fetchall()
    conn.close()

    return render_template("officer/view_all_records.html", records=records)

@app.route("/public/view-record", methods=["GET", "POST"])
def public_view_record():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        survey_number = request.form["survey_number"]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch land record details
        cursor.execute("""
            SELECT * FROM land_records WHERE survey_number = ?
        """, (survey_number,))
        record = cursor.fetchone()

        if not record:
            flash("Record not found.")
            return render_template("public/view_record.html", record=None)

        # Check if the property is listed for sale
        cursor.execute("""
            SELECT * FROM sell_alerts WHERE survey_number = ? AND status = 'active'
        """, (survey_number,))
        sell_alert = cursor.fetchone()

        conn.close()

        return render_template(
            "public/view_record.html",
            record=record,
            sell_alert=sell_alert
        )

    return render_template("public/view_record.html", record=None)

@app.route("/officer/view-record", methods=["GET", "POST"])
def officer_view_record():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    if request.method == "POST":
        survey_number = request.form["survey_number"]

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch land record details
        cursor.execute("""
            SELECT * FROM land_records WHERE survey_number = ?
        """, (survey_number,))
        record = cursor.fetchone()

        if not record:
            flash("Record not found.")
            return render_template("officer/view_record.html", record=None)

        # Fetch ownership transfer history
        cursor.execute("""
            SELECT * FROM ownership_transfer_requests
            WHERE survey_number = ? ORDER BY created_at DESC
        """, (survey_number,))
        transfer_history = cursor.fetchall()

        # Check if the property is listed for sale
        cursor.execute("""
            SELECT * FROM sell_alerts WHERE survey_number = ? AND status = 'active'
        """, (survey_number,))
        sell_alert = cursor.fetchone()

        conn.close()

        return render_template(
            "officer/view_record.html",
            record=record,
            transfer_history=transfer_history,
            sell_alert=sell_alert
        )

    return render_template("officer/view_record.html", record=None)


@app.route("/view-record/<string:survey_number>", methods=["GET"])
def view_record(survey_number):
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch land record details
    cursor.execute("""
        SELECT * FROM land_records WHERE survey_number = ?
    """, (survey_number,))
    record = cursor.fetchone()

    if not record:
        flash("Record not found.")
        return redirect(url_for("owned_properties"))

    # Check if the property is listed for sale
    cursor.execute("""
        SELECT * FROM sell_alerts WHERE survey_number = ? AND status = 'active'
    """, (survey_number,))
    sell_alert = cursor.fetchone()

    conn.close()

    return render_template(
        "public/view_record_details.html",
        record=record,
        sell_alert=sell_alert
    )

# Buyer View Selling Lands
@app.route("/buyer/view-selling-lands")
def buyer_view_selling_lands():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all active sell alerts with land record details
    cursor.execute("""
        SELECT lr.*, sa.seller, sa.created_at AS sale_created_at
        FROM land_records lr
        JOIN sell_alerts sa ON lr.survey_number = sa.survey_number
        WHERE sa.status = 'active'
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
    cursor.execute("""
        SELECT * FROM sell_alerts WHERE survey_number = ? AND status = 'active'
    """, (survey_number,))
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
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests WHERE id = ?
    """, (request_id,))
    transfer_request = cursor.fetchone()

    if not transfer_request or transfer_request["status"] != "pending":
        flash("Invalid or already processed transfer request.")
        conn.close()
        return redirect(url_for("officer_dashboard"))

    # Update the land record with the new owner
    cursor.execute("""
        UPDATE land_records
        SET owner_name = ?
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
    return redirect(url_for("officer_view_pending_transfers"))

@app.route("/seller/transfer-ownership", methods=["GET", "POST"])
def seller_transfer_ownership():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        survey_number = request.form["survey_number"]
        new_owner = request.form["new_owner"]

        # Use the blockchain to transfer ownership
        smart_contract = SmartContract()
        smart_contract.transfer_ownership(survey_number, new_owner)

        # Check if the survey number exists and belongs to the seller
        cursor.execute("""
            SELECT * FROM land_records WHERE survey_number = ? AND owner_name = ?
        """, (survey_number, session["username"]))
        record = cursor.fetchone()

        if not record:
            flash("You do not own this property.")
            conn.close()
            return redirect(url_for("seller_transfer_ownership"))

        # Insert the ownership transfer request with request_type='transfer'
        try:
            cursor.execute("""
                INSERT INTO ownership_transfer_requests (survey_number, current_owner, new_owner, request_type)
                VALUES (?, ?, ?, ?)
            """, (survey_number, session["username"], new_owner, "transfer"))
            conn.commit()
            flash("Ownership transfer request submitted successfully.")
        except Exception as e:
            flash("An error occurred while submitting the transfer request.")
        finally:
            conn.close()

        return redirect(url_for("seller_transfer_ownership"))

    return render_template("seller/transfer_ownership.html")


@app.route("/seller/view-owned-properties")
def seller_view_owned_properties():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    # Fetch owned properties for the logged-in user
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query to fetch land records where owner_name matches the session username
    cursor.execute("""
        SELECT * FROM land_records WHERE owner_name = ?
    """, (session["username"],))
    owned_properties = cursor.fetchall()

    conn.close()

    return render_template("seller/view_owned_properties.html", owned_properties=owned_properties)

# Add Land Record (Officer Only)
@app.route("/add-record", methods=["GET", "POST"])
def add_record():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    if request.method == "POST":
        survey_number = request.form["survey_number"]
        kahata = request.form["kahata"]
        owner_name = request.form["owner_name"]
        father_name = request.form["father_name"]
        village = request.form["village"]
        address = request.form["address"]
        property_size = float(request.form["property_size"])
        size_unit = request.form["size_unit"]  # 'square_feet' or 'acres'
        crop_details = request.form["crop_details"]
        location = request.form["location"]

        # Use the blockchain to add the land record
        smart_contract = SmartContract()
        smart_contract.create_land_record(survey_number, owner_name, location)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO land_records (survey_number, kahata, owner_name, father_name, village, address, property_size, size_unit, crop_details, location, officer_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (survey_number, kahata, owner_name, father_name, village, address, property_size, size_unit, crop_details, location, session["user_id"]))
            conn.commit()
            flash("Land record added successfully.")
        except sqlite3.IntegrityError:
            flash("Survey number already exists!")
        conn.close()
        return redirect(url_for("officer_dashboard"))
    return render_template("officer/add_record.html")

# Public Dashboard
@app.route("/public/dashboard")
def public_dashboard():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch owned properties
    cursor.execute("""
        SELECT * FROM land_records WHERE owner_name = ?
    """, (session["username"],))
    owned_properties = cursor.fetchall()

    # Fetch properties available for sale
    cursor.execute("""
        SELECT lr.*, sa.seller
        FROM land_records lr
        JOIN sell_alerts sa ON lr.survey_number = sa.survey_number
        WHERE sa.status = 'active'
    """)
    selling_lands = cursor.fetchall()

    conn.close()
    return render_template("public/dashboard.html", owned_properties=owned_properties, selling_lands=selling_lands)

# Search Property Route
@app.route("/search-property", methods=["GET", "POST"])
def search_property():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Default empty results
    results = []

    if request.method == "POST":
        # Get search parameters from the form
        survey_number = request.form.get("survey_number")
        kahata = request.form.get("kahata")
        owner_name = request.form.get("owner_name")
        father_name = request.form.get("father_name")
        village = request.form.get("village")
        property_size = request.form.get("property_size")

        # Build the SQL query dynamically based on provided inputs
        query = """
            SELECT * FROM land_records
            WHERE 1=1
        """
        params = []

        if survey_number:
            query += " AND survey_number LIKE ?"
            params.append(f"%{survey_number}%")
        if kahata:
            query += " AND kahata LIKE ?"
            params.append(f"%{kahata}%")
        if owner_name:
            query += " AND owner_name LIKE ?"
            params.append(f"%{owner_name}%")
        if father_name:
            query += " AND father_name LIKE ?"
            params.append(f"%{father_name}%")
        if village:
            query += " AND village LIKE ?"
            params.append(f"%{village}%")
        if property_size:
            query += " AND property_size = ?"
            params.append(property_size)

        # Execute the query
        cursor.execute(query, params)
        results = cursor.fetchall()

    conn.close()

    return render_template("public/search_property.html", results=results)

    return render_template("public/search_property.html")

# Admin Dashboard
@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    return render_template("admin/dashboard.html")

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))


@app.route("/admin/manage-officers", methods=["GET", "POST"])
def manage_officers():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Handle adding a new officer (POST request)
    if request.method == "POST":
        # Delegate officer registration to the /officer/register route
        return redirect(url_for("officer_register"))

    # Fetch all officers
    cursor.execute("""
        SELECT o.id, u.username, o.first_name, o.last_name, o.mobile_number, o.government_proof_type, o.government_proof_id, o.address
        FROM officers o
        JOIN users u ON o.user_id = u.id
    """)
    officers = cursor.fetchall()
    conn.close()

    return render_template("admin/manage_officers.html", officers=officers)

@app.route("/admin/monitor-records")
def monitor_records():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))
    conn = get_db_connection()
    cursor = conn.cursor()
    # Fetch all land records with officer details
    cursor.execute("""
        SELECT lr.*, u.username AS officer_name
        FROM land_records lr
        LEFT JOIN users u ON lr.officer_id = u.id
    """)
    records = cursor.fetchall()
    conn.close()
    return render_template("admin/monitor_records.html", records=records)

@app.route("/admin/profile/<int:user_id>")
def admin_profile(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, a.first_name, a.last_name, a.mobile_number, a.address
        FROM users u
        JOIN admins a ON u.id = a.user_id
        WHERE u.id = ?
    """, (user_id,))
    admin = cursor.fetchone()
    conn.close()
    return render_template("admin/profile.html", admin=admin)

@app.route("/officer/profile/<int:user_id>")
def officer_profile(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.username, o.first_name, o.last_name, o.mobile_number, o.address
        FROM users u
        JOIN officers o ON u.id = o.user_id
        WHERE u.id = ?
    """, (user_id,))
    officer = cursor.fetchone()
    conn.close()
    return render_template("officer/profile.html", officer=officer)

@app.route("/routes")
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ",".join(sorted(rule.methods))
        line = urllib.parse.unquote(f"{rule.endpoint}: {rule} ({methods})")
        output.append(line)
    return "<br>".join(output)

@app.route("/officer/reject-transfer/<int:request_id>", methods=["POST"])
def reject_transfer(request_id):
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the transfer request
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests WHERE id = ?
    """, (request_id,))
    transfer_request = cursor.fetchone()

    if not transfer_request or transfer_request["status"] != "pending":
        flash("Invalid or already processed transfer request.")
        conn.close()
        return redirect(url_for("officer_dashboard"))

    # Mark the transfer request as rejected
    cursor.execute("""
        UPDATE ownership_transfer_requests
        SET status = 'rejected'
        WHERE id = ?
    """, (request_id,))
    conn.commit()
    conn.close()

    flash("Ownership transfer rejected successfully.")
    return redirect(url_for("officer_view_pending_transfers"))

@app.route("/officer/view-pending-transfers")
def officer_view_pending_transfers():
    if session.get("role") != "officer":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all pending transfer requests
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests WHERE status = 'pending'
    """)
    pending_transfers = cursor.fetchall()

    conn.close()

    return render_template("officer/view_pending_transfers.html", pending_transfers=pending_transfers)

@app.route("/debug/ownership-transfer-requests")
def debug_ownership_transfer_requests():
    # Ensure only authorized users (e.g., admin or officer) can access this route
    if session.get("role") not in ["admin", "officer"]:
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all rows from the ownership_transfer_requests table
    cursor.execute("""
        SELECT * FROM ownership_transfer_requests
    """)
    transfer_requests = cursor.fetchall()

    conn.close()

    return render_template("debug/ownership_transfer_requests.html", transfer_requests=transfer_requests)

@app.route("/debug/blockchain")
def debug_blockchain():
    smart_contract = SmartContract()
    return json.dumps(smart_contract.blockchain.chain, indent=4)

@app.template_filter("datetimeformat")
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")

@app.template_filter("tojson")
def tojson(value):
    return json.dumps(value, indent=4)

@app.route("/admin/blockchain-integrity")
def admin_blockchain_integrity():
    if session.get("role") != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    # Fetch the blockchain
    smart_contract = SmartContract()
    blockchain = smart_contract.blockchain.chain

    # Check blockchain integrity
    is_valid = True
    integrity_report = []

    for i in range(1, len(blockchain)):
        current_block = blockchain[i]
        previous_block = blockchain[i - 1]

        # Verify the hash of the previous block
        if current_block["previous_hash"] != Blockchain.hash(previous_block):
            is_valid = False
            integrity_report.append(f"Block {i} has invalid previous_hash.")

        # Verify the proof of work (optional)
        # You can add additional validation logic here if needed

    if is_valid:
        integrity_report.append("Blockchain integrity verified. No tampering detected.")

    return render_template(
        "admin/blockchain_integrity.html",
        blockchain=blockchain,
        integrity_report=integrity_report,
        is_valid=is_valid
    )

@app.route("/initiate-transfer", methods=["POST"])
def initiate_transfer():
    if session.get("role") != "public":
        flash("Unauthorized access!")
        return redirect(url_for("home"))

    survey_number = request.form["survey_number"]
    new_owner = request.form.get("new_owner")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the survey number exists and belongs to the current user
    cursor.execute("""
        SELECT * FROM land_records WHERE survey_number = ? AND owner_name = ?
    """, (survey_number, session["username"]))
    record = cursor.fetchone()

    if not record:
        flash("You do not own this property.")
        conn.close()
        return redirect(url_for("public_dashboard"))

    # Insert the ownership transfer request
    try:
        cursor.execute("""
            INSERT INTO ownership_transfer_requests (survey_number, current_owner, new_owner)
            VALUES (?, ?, ?)
        """, (survey_number, session["username"], new_owner))
        conn.commit()
        flash("Ownership transfer request submitted successfully.")
    except sqlite3.IntegrityError:
        flash("An ownership transfer request already exists for this property.")

    conn.close()
    return redirect(url_for("public_dashboard"))

# @app.context_processor
# def inject_user_role():
#     return {"user_role": session.get("role")}
#
# @app.before_request
# def require_login():
#     allowed_routes = ["login", "register", "home"]  # Routes that don't require login
#     if request.endpoint not in allowed_routes and "role" not in session:
#         flash("You need to log in first.")
#         return redirect(url_for("home"))

if __name__ == "__main__":
    init_db()  # Initialize the database
    create_default_admin()  # Create default admin account
    app.run(debug=True)