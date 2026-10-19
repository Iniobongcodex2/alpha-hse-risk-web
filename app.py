# ============================================
# ALPHA HSE RISK — WEB APP
# ============================================
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import psycopg2
import psycopg2.extras
import os
import hashlib
import datetime

app = Flask(__name__)
app.secret_key = "change-this-secret-key-later-2026"

# ============================================
# DATABASE CONNECTION (Postgres in cloud, SQLite local)
# ============================================
def get_db_connection():
    """Returns a database connection. Uses PostgreSQL if DATABASE_URL is set, else SQLite."""
    db_url = os.environ.get('DATABASE_URL')
    
    if db_url:
        # PostgreSQL (Cloud)
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        return conn
    else:
        # SQLite (Local)
        data_folder = os.path.expanduser("~/Documents/ALPHA_HSE_DATA")
        if not os.path.exists(data_folder):
            os.makedirs(data_folder, exist_ok=True)
        db_path = os.path.join(data_folder, "alpha_hse_risk.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

def verify_password(password, stored_hash):
    """Checks if a plain-text password matches a stored PBKDF2 hash."""
    if not password or not stored_hash:
        return False
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = parts[3]
        pwd_bytes = password.encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations)
        return dk.hex() == expected
    except:
        return False

def calculate_risk_level(score):
    """Returns the risk level based on score."""
    if score >= 16:
        return "Critical"
    elif score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

def setup_database():
    """Creates tables if they don't exist, and seeds the admin user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    is_postgres = os.environ.get('DATABASE_URL') is not None
    id_type = "SERIAL PRIMARY KEY" if is_postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"

    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {id_type}, username TEXT NOT NULL UNIQUE, full_name TEXT,
            email TEXT, role_id INTEGER, organization_name TEXT,
            is_active INTEGER NOT NULL DEFAULT 1, password_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS roles (
            id {id_type}, name TEXT NOT NULL UNIQUE, description TEXT
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS assessments (
            id {id_type}, reference TEXT UNIQUE, organization TEXT,
            department TEXT, location TEXT, assessor TEXT,
            project TEXT, date_created TEXT
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS hazards (
            id {id_type}, assessment_id INTEGER, category TEXT, name TEXT,
            severity INTEGER, likelihood INTEGER, risk_score INTEGER,
            risk_level TEXT, existing_controls TEXT, additional_controls TEXT,
            residual_severity INTEGER, residual_likelihood INTEGER,
            residual_score INTEGER, residual_level TEXT, action TEXT
        )
    """)
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS audit_log (
            id {id_type}, timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            username TEXT, action TEXT, target_type TEXT,
            target_id TEXT, details TEXT
        )
    """)

    roles = [
        ("HSE Officer", "Creates and edits assessments"),
        ("HSE Supervisor", "Reviews team assessments"),
        ("HSE Manager", "Org-wide oversight and analytics"),
        ("Administrator", "Manages users, orgs and system"),
    ]
    
    for role_name, description in roles:
        if is_postgres:
            cursor.execute("INSERT INTO roles (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING", (role_name, description))
        else:
            cursor.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", (role_name, description))

    cursor.execute("SELECT COUNT(*) FROM users")
    row = cursor.fetchone()
    
    if row[0] == 0:
        if is_postgres:
            cursor.execute("SELECT id FROM roles WHERE name = %s", ("Administrator",))
        else:
            cursor.execute("SELECT id FROM roles WHERE name = ?", ("Administrator",))
            
        r = cursor.fetchone()
        admin_role_id = r[0] if r else None

        password = "Prosper123#"
        iterations = 29000
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        password_hash = f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

        if is_postgres:
            cursor.execute("""
                INSERT INTO users (username, full_name, email, role_id, organization_name, is_active, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("God'stime", "Iniobong Eyibio", "godstimeisthebest55@gmail.com", admin_role_id, "Shell oil", 1, password_hash))
        else:
            cursor.execute("""
                INSERT INTO users (username, full_name, email, role_id, organization_name, is_active, password_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("God'stime", "Iniobong Eyibio", "godstimeisthebest55@gmail.com", admin_role_id, "Shell oil", 1, password_hash))

    conn.commit()
    cursor.close()
    conn.close()

# ============================================
# RUN SETUP ON FIRST REQUEST
# ============================================
@app.before_request
def _ensure_db_once():
    if not getattr(app, "_db_ready", False):
        setup_database()
        app._db_ready = True

# ============================================
# ROUTES
# ============================================
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Please enter username and password."
        else:
            try:
                conn = get_db_connection()
                if os.environ.get('DATABASE_URL'):
                    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                    cursor.execute(
                        "SELECT username, full_name, role_id, is_active, password_hash, organization_name "
                        "FROM users WHERE username = %s", (username,)
                    )
                    row = cursor.fetchone()
                else:
                    row = conn.execute(
                        "SELECT username, full_name, role_id, is_active, password_hash, organization_name "
                        "FROM users WHERE username = ?", (username,)
                    ).fetchone()
                conn.close()

                if row is None:
                    error = "Invalid username or password."
                elif not row["is_active"]:
                    error = "This account has been deactivated."
                elif not row["password_hash"]:
                    error = "No password set. Contact administrator."
                elif not verify_password(password, row["password_hash"]):
                    error = "Invalid username or password."
                else:
                    session["username"] = row["username"]
                    session["full_name"] = row["full_name"] or row["username"]
                    session["role_id"] = row["role_id"]
                    session["organization_name"] = row["organization_name"] # SAVED TO SESSION FOR SAAS
                    return redirect(url_for("dashboard"))

            except Exception as e:
                error = f"Database error: {e}"

    return render_template("login.html", error=error, active=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    
    is_admin = session.get("role_id") in (3, 4)
    user_org = session.get("organization_name", "Unknown")

    stats = {
        "total_assessments": 0,
        "total_hazards": 0,
        "high_critical": 0,
        "recent": []
    }
    role_name = "Unknown"

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        
        # --- Get the user's role name ---
        if is_postgres:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT name FROM roles WHERE id = %s", (session.get("role_id"),))
            role_row = cursor.fetchone()
            if role_row: role_name = role_row["name"]
        else:
            role_row = conn.execute("SELECT name FROM roles WHERE id = ?", (session.get("role_id"),)).fetchone()
            if role_row: role_name = role_row["name"]

        # --- Existing Stats Logic (NOW FILTERED BY ORGANIZATION) ---
        if is_postgres:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT COUNT(*) AS c FROM assessments WHERE organization = %s", (user_org,))
            stats["total_assessments"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s", (user_org,))
            stats["total_hazards"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s AND h.residual_level IN ('High', 'Critical')", (user_org,))
            stats["high_critical"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT reference, organization, project, date_created FROM assessments WHERE organization = %s ORDER BY id DESC LIMIT 3", (user_org,))
            stats["recent"] = cursor.fetchall()
        else:
            stats["total_assessments"] = conn.execute("SELECT COUNT(*) AS c FROM assessments WHERE organization = ?", (user_org,)).fetchone()["c"]
            stats["total_hazards"] = conn.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ?", (user_org,)).fetchone()["c"]
            stats["high_critical"] = conn.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ? AND h.residual_level IN ('High', 'Critical')", (user_org,)).fetchone()["c"]
            rows = conn.execute("SELECT reference, organization, project, date_created FROM assessments WHERE organization = ? ORDER BY id DESC LIMIT 3", (user_org,)).fetchall()
            stats["recent"] = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        print("Dashboard DB error:", e)

    return render_template(
        "dashboard.html",
        active="dashboard",
        username=session.get("username"),
        full_name=session.get("full_name"),
        stats=stats,
        role_name=role_name,
        is_admin=is_admin  
    )

@app.route("/new", methods=["GET", "POST"])
def new_assessment():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # SaaS SECURITY: Lock the organization to the user's session!
        organization = session.get("organization_name", "Unknown")
        
        department = request.form.get("department", "").strip()
        location = request.form.get("location", "").strip()
        project = request.form.get("project", "").strip()
        category = request.form.get("category", "").strip()
        hazard_name = request.form.get("hazard_name", "").strip()
        existing_controls = request.form.get("existing_controls", "").strip()
        additional_controls = request.form.get("additional_controls", "").strip()

        try:
            severity = int(request.form.get("severity", 0))
            likelihood = int(request.form.get("likelihood", 0))
            residual_severity = int(request.form.get("residual_severity", 0))
            residual_likelihood = int(request.form.get("residual_likelihood", 0))
        except:
            severity = likelihood = residual_severity = residual_likelihood = 0

        if not organization or not hazard_name:
            return render_template("new_assessment.html", active="new", error="Organization and Hazard Name are required.")
        if not (1 <= severity <= 5) or not (1 <= likelihood <= 5):
            return render_template("new_assessment.html", active="new", error="Severity and Likelihood must be 1-5.")
        if not (1 <= residual_severity <= 5) or not (1 <= residual_likelihood <= 5):
            return render_template("new_assessment.html", active="new", error="Residual values must be 1-5.")

        risk_score = severity * likelihood
        risk_level = calculate_risk_level(risk_score)
        residual_score = residual_severity * residual_likelihood
        residual_level = calculate_risk_level(residual_score)

        if residual_level == "Critical":
            action = "STOP WORK - Immediate action required!"
        elif residual_level == "High":
            action = "Review controls - Action required"
        elif residual_level == "Medium":
            action = "Review controls and monitor"
        else:
            action = "Monitor - No immediate action required"

        reference = "HSE-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            conn = get_db_connection()
            is_postgres = os.environ.get('DATABASE_URL') is not None
            q = "%s" if is_postgres else "?"
            
            if is_postgres:
                cursor = conn.cursor()
                cursor.execute(f"""
                    INSERT INTO assessments
                    (reference, organization, department, location, assessor, project, date_created)
                    VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}) RETURNING id
                """, (reference, organization, department, location, session.get("full_name", session.get("username")), project, date_now))
                assessment_id = cursor.fetchone()[0]
            else:
                cursor = conn.cursor()
                cursor.execute(f"""
                    INSERT INTO assessments
                    (reference, organization, department, location, assessor, project, date_created)
                    VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q})
                """, (reference, organization, department, location, session.get("full_name", session.get("username")), project, date_now))
                assessment_id = cursor.lastrowid

            cursor.execute(f"""
                INSERT INTO hazards
                (assessment_id, category, name, severity, likelihood,
                 risk_score, risk_level, existing_controls, additional_controls,
                 residual_severity, residual_likelihood, residual_score,
                 residual_level, action)
                VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q})
            """, (assessment_id, category, hazard_name, severity, likelihood,
                  risk_score, risk_level, existing_controls, additional_controls,
                  residual_severity, residual_likelihood, residual_score,
                  residual_level, action))

            conn.commit()
            cursor.close()
            conn.close()

            return redirect(url_for("history"))

        except Exception as e:
            return render_template("new_assessment.html", active="new", error=f"Save failed: {e}")

    return render_template("new_assessment.html", active="new")

@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    assessments = []
    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("""
                SELECT a.id, a.reference, a.organization, a.project,
                       a.date_created,
                       COUNT(h.id) AS hazard_count
                FROM assessments a
                LEFT JOIN hazards h ON h.assessment_id = a.id
                WHERE a.organization = %s
                GROUP BY a.id, a.reference, a.organization, a.project, a.date_created
                ORDER BY a.id DESC
                LIMIT 50
            """, (user_org,))
            assessments = cursor.fetchall()
        else:
            rows = conn.execute("""
                SELECT a.id, a.reference, a.organization, a.project,
                       a.date_created,
                       COUNT(h.id) AS hazard_count
                FROM assessments a
                LEFT JOIN hazards h ON h.assessment_id = a.id
                WHERE a.organization = ?
                GROUP BY a.id
                ORDER BY a.id DESC
                LIMIT 50
            """, (user_org,)).fetchall()
            assessments = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        print("History error:", e)
        assessments = []

    return render_template("history.html", active="history", assessments=assessments)

@app.route("/assessment/<int:assessment_id>")
def assessment_detail(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")

    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # SaaS SECURITY: Ensure it belongs to their org!
            cursor.execute("SELECT * FROM assessments WHERE id = %s AND organization = %s", (assessment_id, user_org))
            a_row = cursor.fetchone()

            if a_row is None:
                conn.close()
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(a_row)

            cursor.execute("SELECT * FROM hazards WHERE assessment_id = %s ORDER BY id", (assessment_id,))
            hazards = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
            a_row = conn.execute("SELECT * FROM assessments WHERE id = ? AND organization = ?", (assessment_id, user_org)).fetchone()

            if a_row is None:
                conn.close()
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(a_row)

            h_rows = conn.execute("SELECT * FROM hazards WHERE assessment_id = ? ORDER BY id", (assessment_id,)).fetchall()
            hazards = [dict(r) for r in h_rows]

        conn.close()
        return render_template("assessment_detail.html", active="history", assessment=assessment, hazards=hazards)

    except Exception as e:
        print("Detail page error:", e)
        return f"Error loading assessment: {e}", 500

@app.route("/assessment/<int:assessment_id>/pdf")
def assessment_pdf(assessment_id):
    """Generate and download a PDF copy of one saved risk assessment."""
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")

    from io import BytesIO
    from html import escape
    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
    )

    conn = None
    try:
        conn = get_db_connection()
        is_postgres = bool(os.environ.get("DATABASE_URL"))

        if is_postgres:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # SaaS SECURITY: Ensure it belongs to their org!
            cursor.execute("SELECT * FROM assessments WHERE id = %s AND organization = %s", (assessment_id, user_org))
            assessment_row = cursor.fetchone()
            if assessment_row is None:
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(assessment_row)
            cursor.execute(
                "SELECT * FROM hazards WHERE assessment_id = %s ORDER BY id",
                (assessment_id,),
            )
            hazards = [dict(row) for row in cursor.fetchall()]
            cursor.close()
        else:
            assessment_row = conn.execute(
                "SELECT * FROM assessments WHERE id = ? AND organization = ?", (assessment_id, user_org)
            ).fetchone()
            if assessment_row is None:
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(assessment_row)
            hazard_rows = conn.execute(
                "SELECT * FROM hazards WHERE assessment_id = ? ORDER BY id",
                (assessment_id,),
            ).fetchall()
            hazards = [dict(row) for row in hazard_rows]

        def safe_text(value, fallback="—"):
            if value is None or str(value).strip() == "":
                return fallback
            return escape(str(value))

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30,
            title=f"Risk Assessment {assessment.get('reference') or assessment_id}",
            author="ALPHA HSE RISK",
        )

        styles = getSampleStyleSheet()
        # === BRAND COLORS RESTORED HERE ===
        navy = colors.HexColor("#0A1E3D") 
        gold = colors.HexColor("#C9A84C") 
        light_gray = colors.HexColor("#F4F6F9")

        title_style = ParagraphStyle(
            "AlphaTitle", parent=styles["Heading1"],
            textColor=gold, fontSize=16, leading=20, spaceAfter=5,
        )
        subtitle_style = ParagraphStyle(
            "AlphaSubtitle", parent=styles["Normal"],
            fontSize=9, textColor=colors.grey, spaceAfter=12,
        )
        section_style = ParagraphStyle(
            "AlphaSection", parent=styles["Heading2"],
            textColor=navy, fontSize=11, leading=14, spaceAfter=5,
        )
        cell_style = ParagraphStyle(
            "AlphaCell", parent=styles["Normal"], fontSize=8.5, leading=11,
            wordWrap="CJK",
        )
        label_style = ParagraphStyle(
            "AlphaLabel", parent=cell_style, fontName="Helvetica-Bold",textColor=gold
        )
        footer_style = ParagraphStyle(
            "AlphaFooter", parent=styles["Normal"],
            fontSize=9, textColor=gold, alignment=TA_CENTER,
        )

        def make_table(rows, col_widths, label_column=True):
            formatted = []
            for row in rows:
                formatted.append([
                    Paragraph(safe_text(value), label_style if label_column and index == 0 else cell_style)
                    for index, value in enumerate(row)
                ])
            table = Table(formatted, colWidths=col_widths, repeatRows=0, hAlign="LEFT")
            commands = [
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD2D9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]

            if label_column:
                commands.extend([
                    ("BACKGROUND", (0, 0), (0, -1), navy),
                    ("TEXTCOLOR", (0, 0), (0, -1), gold),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ])
            table.setStyle(TableStyle(commands))
            return table

        elements = [
            Paragraph("ALPHA HSE RISK ASSESSMENT", title_style),
            Paragraph("Professional Risk Management System", subtitle_style),
        ]

        header_data = [
            ["Reference:", assessment.get("reference")],
            ["Organization:", assessment.get("organization")],
            ["Department:", assessment.get("department")],
            ["Location / Site:", assessment.get("location")],
            ["Assessor:", assessment.get("assessor")],
            ["Project:", assessment.get("project")],
            ["Date:", assessment.get("date_created")],
        ]
        elements.append(make_table(header_data, [1.45 * inch, 5.25 * inch]))
        elements.append(Spacer(1, 14))

        if not hazards:
            elements.append(Paragraph("No hazards are recorded for this assessment.", cell_style))

        for index, hazard in enumerate(hazards, 1):
            category = safe_text(hazard.get("category"))
            elements.append(Paragraph(f"HAZARD {index}: {category}", section_style))
            initial_data = [
                ["Hazard Name:", hazard.get("name")],
                ["Severity:", hazard.get("severity")],
                ["Likelihood:", hazard.get("likelihood")],
                ["Initial Risk Score:", f"{hazard.get('risk_score') if hazard.get('risk_score') is not None else '—'} ({hazard.get('risk_level') or '—'})"],
                ["Existing Controls:", hazard.get("existing_controls")],
                ["Additional Controls:", hazard.get("additional_controls")],
                ["Residual Severity:", hazard.get("residual_severity")],
                ["Residual Likelihood:", hazard.get("residual_likelihood")],
                ["Residual Risk Score:", f"{hazard.get('residual_score') if hazard.get('residual_score') is not None else '—'} ({hazard.get('residual_level') or '—'})"],
                ["Action:", hazard.get("action")],
            ]
            elements.append(KeepTogether([
                make_table(initial_data, [1.45 * inch, 5.25 * inch]),
                Spacer(1, 12),
            ]))

        elements.extend([
            Spacer(1, 8),
            HRFlowable(width="100%", thickness=0.6, color=navy, spaceBefore=3, spaceAfter=8),
            Paragraph("SMART SAFETY. STRONG FUTURE.", footer_style),
        ])

        doc.build(elements)
        buffer.seek(0)
        filename_ref = str(assessment.get("reference") or f"assessment-{assessment_id}")
        filename_ref = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in filename_ref)
        filename = f"{filename_ref or f'assessment-{assessment_id}'}.pdf"
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf",
        )

    except Exception as e:
        app.logger.exception("PDF generation failed for assessment %s", assessment_id)
        return f"PDF generation failed. Please check the application log. ({type(e).__name__})", 500
    finally:
        if conn is not None:
            conn.close()

# ============================================
# ADMIN DASHBOARD ROUTES
# ============================================

@app.route("/admin")
def admin_panel():
    if "username" not in session:
        return redirect(url_for("login"))
        
    if session.get("role_id") not in (3, 4):
        return "Access Denied. You do not have permission to view this page.", 403

    user_org = session.get("organization_name")
    users = []
    
    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # SaaS SECURITY: Only show users from the Admin's own organization
            cursor.execute("SELECT username, full_name, organization_name, is_active, role_id FROM users WHERE organization_name = %s ORDER BY id", (user_org,))
            users = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
            # SaaS SECURITY: Same for SQLite
            rows = conn.execute("SELECT username, full_name, organization_name, is_active, role_id FROM users WHERE organization_name = ? ORDER BY id", (user_org,)).fetchall()
            users = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        print("Admin DB error:", e)

    return render_template("admin.html", active="admin", users=users)

@app.route("/admin/toggle_user/<username>", methods=["POST"])
def toggle_user_status(username):
    if "username" not in session or session.get("role_id") not in (3, 4):
        return "Access Denied", 403

    if username == session.get("username"):
        return "You cannot deactivate your own account.", 400

    user_org = session.get("organization_name")

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        # SaaS SECURITY: Check if the user exists AND belongs to the Admin's organization
        cursor.execute(f"SELECT is_active FROM users WHERE username = {q} AND organization_name = {q}", (username, user_org))
        row = cursor.fetchone()
        
        if row:
            current_status = row[0]
            new_status = 0 if current_status == 1 else 1
            
            # SaaS SECURITY: Update only if they belong to the same org
            cursor.execute(f"UPDATE users SET is_active = {q} WHERE username = {q} AND organization_name = {q}", (new_status, username, user_org))
            conn.commit()
            
        cursor.close()
        conn.close()
    except Exception as e:
        print("Toggle user error:", e)

    return redirect(url_for("admin_panel"))

# ============================================

@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template(
        "profile.html",
        active="profile",
        username=session.get("username"),
        full_name=session.get("full_name")
    )

@app.route('/sw.js')
def service_worker():
    from flask import make_response
    response = make_response(app.send_static_file('sw.js'))
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Service-Worker-Allowed'] = '/'
    return response

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
