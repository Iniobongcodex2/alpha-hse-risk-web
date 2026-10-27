# ============================================
# ALPHA HSE RISK — WEB APP
# ============================================
from flask import Flask, render_template, request, redirect, url_for, session, send_file
import sqlite3
import psycopg2
import psycopg2.extras
import os
import hashlib
import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from io import BytesIO
from flask_wtf.csrf import CSRFProtect
import html
from dotenv import load_dotenv
load_dotenv() 
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
app = Flask(__name__)
app.secret_key = "change-this-secret-key-later-2026"
app.permanent_session_lifetime = datetime.timedelta(days=30)

# --- ADD THESE TWO LINES ---
csrf = CSRFProtect(app)
# ---------------------------


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
        # If we are on Render but DATABASE_URL is missing, crash instead of using SQLite!
        if os.environ.get('RENDER'):
            raise Exception("CRITICAL ERROR: DATABASE_URL is missing on Render. Refusing to fallback to SQLite to prevent data loss.")
            
        # SQLite (Local laptop testing only)
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

def log_action(username, action, target_type, target_id, details):
    """Helper function to write an action to the audit_log table."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor.execute(f"""
            INSERT INTO audit_log (username, action, target_type, target_id, details)
            VALUES ({q}, {q}, {q}, {q}, {q})
        """, (username, action, target_type, target_id, details))
        
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Failed to write audit log: {e}")
        
def send_email_notification(to_email, subject, html_content):
    if not to_email:
        return False
        
    api_key = os.environ.get('SENDGRID_API_KEY')
    sender = os.environ.get('SENDER_EMAIL')
    
    if not api_key or not sender:
        print("Email Error: SENDGRID_API_KEY or SENDER_EMAIL missing.")
        return False
        
    try:
        message = Mail(
            from_email=sender,
            to_emails=to_email,
            subject=subject,
            html_content=html_content
        )
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        return response.status_code == 202
    except Exception as e:
        print(f"SendGrid Exception: {type(e).__name__}")
        return False        

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
    
    # NEW TABLE: Observations
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS observations (
            id {id_type}, reference TEXT UNIQUE, organization TEXT,
            reporter TEXT, department TEXT, location TEXT,
            category TEXT, obs_type TEXT, description TEXT,
            priority TEXT, status TEXT, date_reported TEXT
        )
    """)
    
    # NEW TABLE: Corrective Actions
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS corrective_actions (
            id {id_type}, observation_ref TEXT, organization TEXT,
            action_desc TEXT, assigned_to TEXT, due_date TEXT, 
            status TEXT, date_assigned TEXT
        )
    """)
    
    # NEW TABLE: Management Activities
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS mgmt_activities (
            id {id_type}, reference TEXT UNIQUE, organization TEXT,
            activity_type TEXT, manager_name TEXT, activity_date TEXT,
            location TEXT, findings TEXT, status TEXT
        )
    """)

    # --- NEW TABLE: Notification Log (Stage A) ---
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS notification_log (
            id {id_type}, 
            action_id INTEGER,
            notification_type TEXT,
            target_date TEXT,
            status TEXT DEFAULT 'PENDING',
            locked_until TEXT,
            worker_token TEXT,
            UNIQUE(action_id, notification_type, target_date)
        )
    """)
    # --------------------------------------------

    # IDEMPOTENT MIGRATIONS (Safe for existing databases)
    if is_postgres:
        cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='corrective_actions'")
        existing_cols = [row[0] for row in cursor.fetchall()]
    else:
        cursor.execute("PRAGMA table_info(corrective_actions)")
        existing_cols = [row[1] for row in cursor.fetchall()]

    if 'completion_notes' not in existing_cols:
        cursor.execute("ALTER TABLE corrective_actions ADD COLUMN completion_notes TEXT")
    if 'completed_date' not in existing_cols:
        cursor.execute("ALTER TABLE corrective_actions ADD COLUMN completed_date TEXT")
    if 'verified_by' not in existing_cols:
        cursor.execute("ALTER TABLE corrective_actions ADD COLUMN verified_by TEXT")
    if 'verified_date' not in existing_cols:
        cursor.execute("ALTER TABLE corrective_actions ADD COLUMN verified_date TEXT")
    if 'completed_by' not in existing_cols:
        cursor.execute("ALTER TABLE corrective_actions ADD COLUMN completed_by TEXT")

    # Seed Roles
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

    # Seed Admin User
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
                    session.permanent = True 
                    session["username"] = row["username"]
                    session["full_name"] = row["full_name"] or row["username"]
                    session["role_id"] = row["role_id"]
                    session["organization_name"] = row["organization_name"] 
                    log_action(row["username"], "LOGIN", "User", row["username"], "Successful login")
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
        "total_observations": 0,  # <--- NEW
        "open_actions": 0,        # <--- NEW
        "overdue_actions": 0,     # <--- NEW
        "mgmt_activities": 0,     # <--- NEW
        "recent": []
    }
    role_name = "Unknown"
    risk_dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    top_categories = []

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        
        if is_postgres:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT name FROM roles WHERE id = %s", (session.get("role_id"),))
            role_row = cursor.fetchone()
            if role_row: role_name = role_row["name"]

            cursor.execute("SELECT COUNT(*) AS c FROM assessments WHERE organization = %s", (user_org,))
            stats["total_assessments"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s", (user_org,))
            stats["total_hazards"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s AND h.residual_level IN ('High', 'Critical')", (user_org,))
            stats["high_critical"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT reference, organization, project, date_created FROM assessments WHERE organization = %s ORDER BY id DESC LIMIT 5", (user_org,))
            stats["recent"] = cursor.fetchall()

            cursor.execute("SELECT h.residual_level, COUNT(*) as count FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s GROUP BY h.residual_level", (user_org,))
            for row in cursor.fetchall():
                if row["residual_level"] in risk_dist:
                    risk_dist[row["residual_level"]] = row["count"]

            cursor.execute("SELECT h.category, COUNT(*) as count FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = %s GROUP BY h.category ORDER BY count DESC LIMIT 5", (user_org,))
            top_categories = [dict(row) for row in cursor.fetchall()]

            # --- NEW KPI QUERIES (POSTGRES) ---
            cursor.execute("SELECT COUNT(*) AS c FROM observations WHERE organization = %s", (user_org,))
            stats["total_observations"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM corrective_actions WHERE organization = %s AND status = 'Open'", (user_org,))
            stats["open_actions"] = cursor.fetchone()["c"]
            
            today_date = datetime.datetime.now().strftime("%Y-%m-%d")
            cursor.execute("SELECT COUNT(*) AS c FROM corrective_actions WHERE organization = %s AND status = 'Open' AND due_date < %s", (user_org, today_date))
            stats["overdue_actions"] = cursor.fetchone()["c"]
            
            cursor.execute("SELECT COUNT(*) AS c FROM mgmt_activities WHERE organization = %s", (user_org,))
            stats["mgmt_activities"] = cursor.fetchone()["c"]

        else:
            role_row = conn.execute("SELECT name FROM roles WHERE id = ?", (session.get("role_id"),)).fetchone()
            if role_row: role_name = role_row["name"]

            stats["total_assessments"] = conn.execute("SELECT COUNT(*) AS c FROM assessments WHERE organization = ?", (user_org,)).fetchone()["c"]
            stats["total_hazards"] = conn.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ?", (user_org,)).fetchone()["c"]
            stats["high_critical"] = conn.execute("SELECT COUNT(*) AS c FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ? AND h.residual_level IN ('High', 'Critical')", (user_org,)).fetchone()["c"]
            
            rows = conn.execute("SELECT reference, organization, project, date_created FROM assessments WHERE organization = ? ORDER BY id DESC LIMIT 5", (user_org,)).fetchall()
            stats["recent"] = [dict(r) for r in rows]

            dist_rows = conn.execute("SELECT h.residual_level, COUNT(*) as count FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ? GROUP BY h.residual_level", (user_org,)).fetchall()
            for row in dist_rows:
                if row["residual_level"] in risk_dist:
                    risk_dist[row["residual_level"]] = row["count"]

            cat_rows = conn.execute("SELECT h.category, COUNT(*) as count FROM hazards h JOIN assessments a ON h.assessment_id = a.id WHERE a.organization = ? GROUP BY h.category ORDER BY count DESC LIMIT 5", (user_org,)).fetchall()
            top_categories = [dict(r) for r in cat_rows]

            # --- NEW KPI QUERIES (SQLITE) ---
            stats["total_observations"] = conn.execute("SELECT COUNT(*) AS c FROM observations WHERE organization = ?", (user_org,)).fetchone()["c"]
            stats["open_actions"] = conn.execute("SELECT COUNT(*) AS c FROM corrective_actions WHERE organization = ? AND status = 'Open'", (user_org,)).fetchone()["c"]
            
            today_date = datetime.datetime.now().strftime("%Y-%m-%d")
            stats["overdue_actions"] = conn.execute("SELECT COUNT(*) AS c FROM corrective_actions WHERE organization = ? AND status = 'Open' AND due_date < ?", (user_org, today_date)).fetchone()["c"]
            stats["mgmt_activities"] = conn.execute("SELECT COUNT(*) AS c FROM mgmt_activities WHERE organization = ?", (user_org,)).fetchone()["c"]

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
        is_admin=is_admin,
        risk_dist=risk_dist,
        top_categories=top_categories
    )

@app.route("/dashboard/report")
def management_report():
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from io import BytesIO
    from flask import send_file

    conn = None
    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        # 1. Fetch KPIs
        stats = {"obs": 0, "open_actions": 0, "overdue_actions": 0, "mgmt": 0}
        today_date = datetime.datetime.now().strftime("%Y-%m-%d")
        
        cursor.execute(f"SELECT COUNT(*) FROM observations WHERE organization = {q}", (user_org,))
        stats["obs"] = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM corrective_actions WHERE organization = {q} AND status IN ('Open', 'In Progress')", (user_org,))
        stats["open_actions"] = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM corrective_actions WHERE organization = {q} AND status IN ('Open', 'In Progress') AND due_date < {q}", (user_org, today_date))
        stats["overdue_actions"] = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM mgmt_activities WHERE organization = {q}", (user_org,))
        stats["mgmt"] = cursor.fetchone()[0]

        # 2. Fetch Open/Overdue Actions
        cursor.execute(f"SELECT action_desc, assigned_to, due_date, status FROM corrective_actions WHERE organization = {q} AND status IN ('Open', 'In Progress') ORDER BY due_date ASC LIMIT 15", (user_org,))
        open_actions = cursor.fetchall()

        # 3. Fetch Recent Observations
        cursor.execute(f"SELECT reference, category, priority, date_reported FROM observations WHERE organization = {q} ORDER BY id DESC LIMIT 10", (user_org,))
        recent_obs = cursor.fetchall()

        cursor.close()
        conn.close()

        # --- BUILD THE PDF ---
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30,
            title=f"HSE Management Report - {user_org}", author="ALPHA HSE RISK"
        )

        styles = getSampleStyleSheet()
        navy = colors.HexColor("#0A1E3D")
        gold = colors.HexColor("#C9A84C")

        title_style = ParagraphStyle("T", parent=styles["Heading1"], textColor=gold, fontSize=16, spaceAfter=5)
        sub_style = ParagraphStyle("S", parent=styles["Normal"], fontSize=10, textColor=colors.grey, spaceAfter=15)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"], textColor=navy, fontSize=12, spaceBefore=15, spaceAfter=10)
        cell_style = ParagraphStyle("C", parent=styles["Normal"], fontSize=8, leading=10, wordWrap="CJK")
        label_style = ParagraphStyle("L", parent=cell_style, fontName="Helvetica-Bold", textColor=gold)

        elements = [
            Paragraph("ALPHA HSE RISK - MANAGEMENT REPORT", title_style),
            Paragraph(f"Organization: {user_org} | Date: {datetime.datetime.now().strftime('%Y-%m-%d')}", sub_style),
            HRFlowable(width="100%", thickness=1, color=navy, spaceAfter=10)
        ]

        # KPI Table
        elements.append(Paragraph("HSE Performance KPIs", h2_style))
        kpi_data = [
            ["Total Observations", "Open Actions", "Overdue Actions", "Mgmt Activities"],
            [str(stats["obs"]), str(stats["open_actions"]), str(stats["overdue_actions"]), str(stats["mgmt"])]
        ]
        kpi_table = Table(kpi_data, colWidths=[1.5*inch]*4, hAlign="CENTER")
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), navy),
            ('TEXTCOLOR', (0, 0), (-1, 0), gold),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(kpi_table)

        # Open Actions Table
        elements.append(Paragraph("Active & Overdue Corrective Actions", h2_style))
        if open_actions:
            action_data = [["Action Required", "Assigned To", "Due Date", "Status"]]
            for a in open_actions:
                action_data.append([
                    Paragraph(str(a[0]), cell_style), Paragraph(str(a[1]), cell_style), 
                    Paragraph(str(a[2]), cell_style), Paragraph(str(a[3]), cell_style)
                ])
            action_table = Table(action_data, colWidths=[3.2*inch, 1.2*inch, 1*inch, 1*inch], hAlign="LEFT")
            action_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), navy),
                ('TEXTCOLOR', (0, 0), (-1, 0), gold),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            elements.append(action_table)
        else:
            elements.append(Paragraph("No active corrective actions.", cell_style))

        # Recent Observations Table
        elements.append(Paragraph("Recent Observations", h2_style))
        if recent_obs:
            obs_data = [["Reference", "Category", "Priority", "Date"]]
            for o in recent_obs:
                obs_data.append([
                    Paragraph(str(o[0]), cell_style), Paragraph(str(o[1]), cell_style), 
                    Paragraph(str(o[2]), cell_style), Paragraph(str(o[3]), cell_style)
                ])
            obs_table = Table(obs_data, colWidths=[2*inch, 2*inch, 1.2*inch, 1.2*inch], hAlign="LEFT")
            obs_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), navy),
                ('TEXTCOLOR', (0, 0), (-1, 0), gold),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            elements.append(obs_table)
        else:
            elements.append(Paragraph("No observations recorded.", cell_style))

        # Watermark & Footer
        def add_watermark(canvas, doc):
            canvas.saveState()
            canvas.setFont('Helvetica-Bold', 60)
            canvas.setFillColor(navy)
            canvas.setFillAlpha(0.05)
            canvas.translate(300, 400)
            canvas.rotate(45)
            canvas.drawCentredString(0, 0, "ALPHA HSE RISK")
            canvas.restoreState()

        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(width="100%", thickness=1, color=navy))
        elements.append(Paragraph("SMART SAFETY. STRONG FUTURE.", ParagraphStyle("F", parent=cell_style, alignment=1, textColor=gold, spaceBefore=10)))

        doc.build(elements, onFirstPage=add_watermark, onLaterPages=add_watermark)
        buffer.seek(0)

        filename = f"Management_Report_{user_org.replace(' ', '_')}_{datetime.datetime.now().strftime('%Y%m%d')}.pdf"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")

    except Exception as e:
        app.logger.exception("Failed to generate management report")
        return f"Failed to generate report: {e}", 500

@app.route("/new", methods=["GET", "POST"])
def new_assessment():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        organization = session.get("organization_name", "Unknown")
        department = request.form.get("department", "").strip()
        location = request.form.get("location", "").strip()
        project = request.form.get("project", "").strip()
        
        categories = request.form.getlist("category[]")
        custom_categories = request.form.getlist("custom_category[]")
        hazard_names = request.form.getlist("hazard_name[]")
        severities = request.form.getlist("severity[]")
        likelihoods = request.form.getlist("likelihood[]")
        existing_controls_list = request.form.getlist("existing_controls[]")
        additional_controls_list = request.form.getlist("additional_controls[]")
        residual_severities = request.form.getlist("residual_severity[]")
        residual_likelihoods = request.form.getlist("residual_likelihood[]")

        if not organization or not hazard_names:
            return render_template("new_assessment.html", active="new", error="Organization and at least one Hazard are required.")

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

            for i in range(len(hazard_names)):
                cat = categories[i]
                if cat == "Custom":
                    cat = custom_categories[i]
                
                sev = int(severities[i])
                lik = int(likelihoods[i])
                res_sev = int(residual_severities[i])
                res_lik = int(residual_likelihoods[i])

                risk_score = sev * lik
                risk_level = calculate_risk_level(risk_score)
                residual_score = res_sev * res_lik
                residual_level = calculate_risk_level(residual_score)

                if residual_level == "Critical":
                    action = "STOP WORK - Immediate action required!"
                elif residual_level == "High":
                    action = "Review controls - Action required"
                elif residual_level == "Medium":
                    action = "Review controls and monitor"
                else:
                    action = "Monitor - No immediate action required"

                cursor.execute(f"""
                    INSERT INTO hazards
                    (assessment_id, category, name, severity, likelihood,
                     risk_score, risk_level, existing_controls, additional_controls,
                     residual_severity, residual_likelihood, residual_score,
                     residual_level, action)
                    VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q})
                """, (assessment_id, cat, hazard_names[i], sev, lik,
                      risk_score, risk_level, existing_controls_list[i], additional_controls_list[i],
                      res_sev, res_lik, residual_score, residual_level, action))

            conn.commit()
            cursor.close()
            conn.close()

            log_action(session.get("username"), "CREATE_ASSESSMENT", "Assessment", reference, "Created new multi-hazard assessment")
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

@app.route("/assessment/<int:assessment_id>/delete", methods=["POST"])
def delete_assessment(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    deleted = False

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT id FROM assessments WHERE id = {q} AND organization = {q}", (assessment_id, user_org))
        row = cursor.fetchone()
        
        if row:
            cursor.execute(f"DELETE FROM hazards WHERE assessment_id = {q}", (assessment_id,))
            cursor.execute(f"DELETE FROM assessments WHERE id = {q}", (assessment_id,))
            conn.commit()
            deleted = True
            
        cursor.close()
        conn.close()
    except Exception as e:
        print("Delete assessment error:", e)

    if deleted:
        log_action(session.get("username"), "DELETE_ASSESSMENT", "Assessment", str(assessment_id), "Deleted an assessment")

    return redirect(url_for("history"))

@app.route("/assessment/<int:assessment_id>/pdf")
def assessment_pdf(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")

    from html import escape
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
        navy = colors.HexColor("#0A1E3D") 
        gold = colors.HexColor("#C9A84C") 

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
            Paragraph("Generated by ALPHA HSE RISK v2.0 | Alpha Software developer", 
                      ParagraphStyle("Watermark", parent=footer_style, fontSize=7, textColor=colors.grey, spaceBefore=4)),
        ])

        def add_watermark(canvas, doc):
            canvas.saveState()
            canvas.setFont('Helvetica-Bold', 60)
            canvas.setFillColor(colors.HexColor("#0A1E3D"))
            canvas.setFillAlpha(0.05)
            canvas.translate(300, 400)
            canvas.rotate(45)
            canvas.drawCentredString(0, 0, "ALPHA HSE RISK")
            canvas.restoreState()

        doc.build(elements, onFirstPage=add_watermark, onLaterPages=add_watermark)
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

@app.route("/assessment/<int:assessment_id>/excel")
def assessment_excel(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")

    conn = None
    try:
        conn = get_db_connection()
        is_postgres = bool(os.environ.get("DATABASE_URL"))

        if is_postgres:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM assessments WHERE id = %s AND organization = %s", (assessment_id, user_org))
            assessment_row = cursor.fetchone()
            if assessment_row is None:
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(assessment_row)
            cursor.execute("SELECT * FROM hazards WHERE assessment_id = %s ORDER BY id", (assessment_id,))
            hazards = [dict(row) for row in cursor.fetchall()]
            cursor.close()
        else:
            assessment_row = conn.execute("SELECT * FROM assessments WHERE id = ? AND organization = ?", (assessment_id, user_org)).fetchone()
            if assessment_row is None:
                return "Access Denied: This assessment belongs to another organization.", 403
            assessment = dict(assessment_row)
            hazard_rows = conn.execute("SELECT * FROM hazards WHERE assessment_id = ? ORDER BY id", (assessment_id,)).fetchall()
            hazards = [dict(row) for row in hazard_rows]

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Risk Assessment"

        navy_fill = PatternFill(start_color="0A1E3D", end_color="0A1E3D", fill_type="solid")
        gold_font = Font(color="C9A84C", bold=True)
        bold_font = Font(bold=True)
        wrap_alignment = Alignment(wrap_text=True, vertical="top")

        ws.append(["ALPHA HSE RISK ASSESSMENT"])
        ws["A1"].font = Font(size=16, bold=True, color="C9A84C")
        ws.append([])
        
        info = [
            ("Reference:", assessment.get("reference")),
            ("Organization:", assessment.get("organization")),
            ("Department:", assessment.get("department")),
            ("Location / Site:", assessment.get("location")),
            ("Assessor:", assessment.get("assessor")),
            ("Project:", assessment.get("project")),
            ("Date:", assessment.get("date_created")),
        ]
        for key, val in info:
            ws.append([key, val])
            ws.cell(row=ws.max_row, column=1).font = bold_font

        ws.append([]) 

        headers = ["Category", "Hazard Name", "Severity", "Likelihood", "Initial Score", "Initial Level", 
                   "Existing Controls", "Additional Controls", "Res. Severity", "Res. Likelihood", 
                   "Residual Score", "Residual Level", "Action"]
        ws.append(headers)
        
        header_row = ws.max_row
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=header_row, column=col)
            cell.fill = navy_fill
            cell.font = gold_font
            cell.alignment = Alignment(horizontal="center")

        for h in hazards:
            ws.append([
                h.get("category"), h.get("name"), h.get("severity"), h.get("likelihood"),
                h.get("risk_score"), h.get("risk_level"), h.get("existing_controls"), h.get("additional_controls"),
                h.get("residual_severity"), h.get("residual_likelihood"), h.get("residual_score"),
                h.get("residual_level"), h.get("action")
            ])
            current_row = ws.max_row
            for col in range(1, len(headers) + 1):
                ws.cell(row=current_row, column=col).alignment = wrap_alignment

        for col in ws.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 40)
            ws.column_dimensions[column].width = adjusted_width

        buffer = BytesIO()
        wb.save(buffer)
        buffer.seek(0)

        filename_ref = str(assessment.get("reference") or f"assessment-{assessment_id}")
        filename_ref = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in filename_ref)
        filename = f"{filename_ref or f'assessment-{assessment_id}'}.xlsx"
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    except Exception as e:
        app.logger.exception("Excel generation failed for assessment %s", assessment_id)
        return f"Excel generation failed. Please check the application log. ({type(e).__name__})", 500
    finally:
        if conn is not None:
            conn.close()

# ============================================
# ADMIN DASHBOARD ROUTES
# ============================================

@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    if "username" not in session or session.get("role_id") not in (3, 4):
        return "Access Denied", 403

    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    role_id = request.form.get("role_id")
    password = request.form.get("password", "")
    
    organization_name = request.form.get("organization_name", "").strip()
    if not organization_name:
        organization_name = session.get("organization_name", "Unknown")

    if username and password and full_name:
        iterations = 29000
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        password_hash = f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"

        try:
            conn = get_db_connection()
            is_postgres = os.environ.get('DATABASE_URL') is not None
            q = "%s" if is_postgres else "?"
            
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO users (username, full_name, email, role_id, organization_name, is_active, password_hash)
                VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q})
            """, (username, full_name, email, role_id, organization_name, 1, password_hash))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            log_action(session.get("username"), "CREATE_USER", "User", username, f"Created new user in {organization_name}")
            
        except Exception as e:
            print(f"Error creating user: {e}")

    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_user/<username>", methods=["POST"])
def delete_user(username):
    if "username" not in session or session.get("role_id") not in (3, 4):
        return "Access Denied", 403

    if username == session.get("username"):
        return "You cannot delete your own account.", 400

    user_org = session.get("organization_name")

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        cursor.execute(f"DELETE FROM users WHERE username = {q} AND organization_name = {q}", (username, user_org))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        log_action(session.get("username"), "DELETE_USER", "User", username, f"Deleted user {username}")
        
    except Exception as e:
        print("Delete user error:", e)

    return redirect(url_for("admin_panel"))

@app.route("/admin/reset_password/<username>", methods=["POST"])
def admin_reset_password(username):
    if "username" not in session or session.get("role_id") not in (3, 4):
        return "Access Denied", 403

    default_password = "Password123!"
    
    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", default_password.encode("utf-8"), salt, 29000)
        password_hash = f"pbkdf2_sha256$29000${salt.hex()}${dk.hex()}"
        
        cursor.execute(f"UPDATE users SET password_hash = {q} WHERE username = {q} AND organization_name = {q}", (password_hash, username, session.get("organization_name")))
        conn.commit()
        cursor.close()
        conn.close()
        
        log_action(session.get("username"), "RESET_PASSWORD", "User", username, "Reset password to default")
        
    except Exception as e:
        print("Reset password error:", e)

    return redirect(url_for("admin_panel"))

@app.route("/admin/audit")
def admin_audit():
    if "username" not in session or session.get("role_id") not in (3, 4):
        return "Access Denied", 403

    user_org = session.get("organization_name")
    logs = []
    
    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("""
                SELECT a.* FROM audit_log a
                JOIN users u ON a.username = u.username
                WHERE u.organization_name = %s
                ORDER BY a.id DESC LIMIT 100
            """, (user_org,))
            logs = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
            logs_raw = conn.execute("""
                SELECT a.* FROM audit_log a
                JOIN users u ON a.username = u.username
                WHERE u.organization_name = ?
                ORDER BY a.id DESC LIMIT 100
            """, (user_org,)).fetchall()
            logs = [dict(r) for r in logs_raw]
        conn.close()
    except Exception as e:
        print("Audit DB error:", e)

    return render_template("audit.html", active="admin", logs=logs)

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
            cursor.execute("SELECT username, full_name, organization_name, is_active, role_id FROM users WHERE organization_name = %s ORDER BY id", (user_org,))
            users = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
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
    new_status = 0

    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT is_active FROM users WHERE username = {q} AND organization_name = {q}", (username, user_org))
        row = cursor.fetchone()
        
        if row:
            current_status = row[0]
            new_status = 0 if current_status == 1 else 1
            
            cursor.execute(f"UPDATE users SET is_active = {q} WHERE username = {q} AND organization_name = {q}", (new_status, username, user_org))
            conn.commit()
            
        cursor.close()
        conn.close()
        
        log_action(session.get("username"), "TOGGLE_USER", "User", username, f"Changed active status to {new_status}")
            
    except Exception as e:
        print("Toggle user error:", e)

    return redirect(url_for("admin_panel"))

# ============================================
@app.route("/observations")
def observations_register():
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    observations = []
    
    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM observations WHERE organization = %s ORDER BY id DESC", (user_org,))
            observations = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM observations WHERE organization = ? ORDER BY id DESC", (user_org,)).fetchall()
            observations = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        print("Observation DB error:", e)

    return render_template("observations.html", active="observations", observations=observations)

@app.route("/raise-observation", methods=["GET", "POST"])
def raise_observation():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        organization = session.get("organization_name", "Unknown")
        reporter = session.get("full_name", session.get("username"))
        
        department = request.form.get("department", "").strip()
        location = request.form.get("location", "").strip()
        category = request.form.get("category", "").strip()
        obs_type = request.form.get("obs_type", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "").strip()

        reference = "OBS-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "New"

        try:
            conn = get_db_connection()
            is_postgres = os.environ.get('DATABASE_URL') is not None
            q = "%s" if is_postgres else "?"
            
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO observations
                (reference, organization, reporter, department, location, category, obs_type, description, priority, status, date_reported)
                VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q}, {q})
            """, (reference, organization, reporter, department, location, category, obs_type, description, priority, status, date_now))
            
            conn.commit()
            cursor.close()
            conn.close()

            log_action(session.get("username"), "RAISE_OBSERVATION", "Observation", reference, f"Raised a {category} observation")
            return redirect(url_for("observations_register"))

        except Exception as e:
            return render_template("raise_observation.html", active="observations", error=f"Save failed: {e}")

    return render_template("raise_observation.html", active="observations")

@app.route("/observation/<int:obs_id>", methods=["GET", "POST"])
def observation_detail(obs_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    
    # Handle assigning a new action
    if request.method == "POST":
        action_desc = request.form.get("action_desc", "").strip()
        assigned_to = request.form.get("assigned_to", "").strip()
        due_date = request.form.get("due_date", "").strip()
        
        conn = None
        try:
            conn = get_db_connection()
            is_postgres = os.environ.get('DATABASE_URL') is not None
            q = "%s" if is_postgres else "?"
            
            cursor = conn.cursor()
            
            # --- Strict Server-Side Validation (Stage A) ---
            cursor.execute(f"SELECT id FROM users WHERE full_name = {q} AND organization_name = {q} AND is_active = 1", (assigned_to, user_org))
            valid_user = cursor.fetchone()
            if not valid_user:
                return "Error: The selected assignee is invalid, inactive, or does not belong to your organization.", 400
            # ----------------------------------------------------

            # Get the observation reference for linking
            if is_postgres:
                cursor.execute("SELECT reference FROM observations WHERE id = %s AND organization = %s", (obs_id, user_org))
            else:
                cursor.execute("SELECT reference FROM observations WHERE id = ? AND organization = ?", (obs_id, user_org))
            obs_row = cursor.fetchone()
            
            if obs_row:
                obs_ref = obs_row[0]
                date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                cursor.execute(f"""
                    INSERT INTO corrective_actions
                    (observation_ref, organization, action_desc, assigned_to, due_date, status, date_assigned)
                    VALUES ({q}, {q}, {q}, {q}, {q}, 'Open', {q})
                """, (obs_ref, user_org, action_desc, assigned_to, due_date, date_now))
                
                # Update observation status to 'Action Assigned'
                cursor.execute(f"UPDATE observations SET status = 'Action Assigned' WHERE id = {q}", (obs_id,))
                
                # --- SAVE TO DATABASE FIRST ---
                conn.commit()
                
                # --- NEW: SEND ASSIGNMENT EMAIL (Safe Post-Commit) ---
                try:
                    # Look up the user's email securely within the same organization
                    cursor.execute(f"SELECT email FROM users WHERE full_name = {q} AND organization_name = {q}", (assigned_to, user_org))
                    user_row = cursor.fetchone()
                    
                    if user_row:
                        email_addr = user_row['email'] if is_postgres else user_row['email']
                        
                        if email_addr:
                            subject = f"New Action Assigned: {obs_ref}"
                            # Escape the text so it can't inject HTML into the email
                            safe_desc = html.escape(action_desc)
                            safe_date = html.escape(due_date)
                            
                            body = f"""
                            <div style="font-family: Arial, sans-serif; padding: 20px; background: #F3F4F6;">
                                <h2 style="color: #0A1E3D;">New Corrective Action Assigned</h2>
                                <p><strong>Observation:</strong> {obs_ref}</p>
                                <p><strong>Action Required:</strong> {safe_desc}</p>
                                <p><strong>Due Date:</strong> {safe_date}</p>
                                <br>
                                <a href="https://alpha-hse-risk-web.onrender.com/observation/{obs_id}" style="background: #0A1E3D; color: #C9A84C; padding: 10px 15px; text-decoration: none; border-radius: 5px; font-weight: bold;">Log in to view</a>
                                <br><br>
                                <p style="font-size: 12px; color: #6B7280;">SMART SAFETY. STRONG FUTURE.</p>
                            </div>
                            """
                            send_email_notification(email_addr, subject, body)
                except Exception as mail_err:
                    print(f"Non-fatal email error: {type(mail_err).__name__}")
                # ------------------------------------------------------
                
                # Audit Log
                log_action(session.get("username"), "ASSIGN_ACTION", "Observation", obs_ref, f"Assigned action to {assigned_to}")
            
            cursor.close()
            return redirect(url_for("observation_detail", obs_id=obs_id))
        except Exception as e:
            if conn: conn.rollback()
            print("Error adding action:", e)
            return "Database error occurred.", 500
        finally:
            if conn: conn.close()

    # --- GET REQUEST LOGIC STARTS HERE ---
    obs = None
    actions = []
    users = []
    conn = None
    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) if is_postgres else conn.cursor()
        
        cursor.execute(f"SELECT * FROM observations WHERE id = {q} AND organization = {q}", (obs_id, user_org))
        obs = cursor.fetchone()
        
        if obs:
            cursor.execute(f"SELECT * FROM corrective_actions WHERE observation_ref = {q} AND organization = {q} ORDER BY id DESC", (obs["reference"] if is_postgres else obs["reference"], user_org))
            actions = cursor.fetchall()
            
        # Fetch eligible users for dropdown
        cursor.execute(f"SELECT full_name FROM users WHERE organization_name = {q} AND is_active = 1 ORDER BY full_name ASC", (user_org,))
        users = cursor.fetchall()
        
        cursor.close()
    except Exception as e:
        print(f"Observation GET Error: {type(e).__name__}")
    finally:
        if conn: conn.close()

    if not obs:
        return "Observation not found or access denied.", 404

    return render_template("observation_detail.html", active="observations", obs=obs, actions=actions, users=users)
@app.route("/management-engagement")
def management_engagement():
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    activities = []
    
    try:
        conn = get_db_connection()
        if os.environ.get('DATABASE_URL'):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM mgmt_activities WHERE organization = %s ORDER BY id DESC", (user_org,))
            activities = cursor.fetchall()
        else:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM mgmt_activities WHERE organization = ? ORDER BY id DESC", (user_org,)).fetchall()
            activities = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        print("Mgmt DB error:", e)

    return render_template("management_engagement.html", active="management", activities=activities)

@app.route("/log-activity", methods=["GET", "POST"])
def log_activity():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        organization = session.get("organization_name", "Unknown")
        manager_name = session.get("full_name", session.get("username"))
        
        activity_type = request.form.get("activity_type", "").strip()
        activity_date = request.form.get("activity_date", "").strip()
        location = request.form.get("location", "").strip()
        findings = request.form.get("findings", "").strip()

        reference = "MGT-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        status = "Completed"

        try:
            conn = get_db_connection()
            is_postgres = os.environ.get('DATABASE_URL') is not None
            q = "%s" if is_postgres else "?"
            
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO mgmt_activities
                (reference, organization, activity_type, manager_name, activity_date, location, findings, status)
                VALUES ({q}, {q}, {q}, {q}, {q}, {q}, {q}, {q})
            """, (reference, organization, activity_type, manager_name, activity_date, location, findings, status))
            
            conn.commit()
            cursor.close()
            conn.close()

            log_action(session.get("username"), "LOG_MGMT_ACTIVITY", "Management", reference, f"Logged a {activity_type}")
            return redirect(url_for("management_engagement"))

        except Exception as e:
            return render_template("log_activity.html", active="management", error=f"Save failed: {e}")

    return render_template("log_activity.html", active="management")

@app.route("/action/<int:action_id>/edit", methods=["POST"])
def edit_action(action_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    new_desc = request.form.get("action_desc", "").strip()
    new_assignee = request.form.get("assigned_to", "").strip()
    new_due_date = request.form.get("due_date", "").strip()

    if not new_desc or not new_assignee or not new_due_date:
        return "All fields are required for editing.", 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT id FROM corrective_actions WHERE id = {q} AND organization = {q}", (action_id, user_org))
        if not cursor.fetchone():
            return "Action not found or unauthorized.", 404

        cursor.execute(f"""
            UPDATE corrective_actions 
            SET action_desc = {q}, assigned_to = {q}, due_date = {q}
            WHERE id = {q} AND organization = {q}
        """, (new_desc, new_assignee, new_due_date, action_id, user_org))
        
        cursor.execute(f"""
            INSERT INTO audit_log (username, action, target_type, target_id, details)
            VALUES ({q}, {q}, {q}, {q}, {q})
        """, (session.get("username"), "EDIT_ACTION", "CorrectiveAction", str(action_id), f"Edited action details"))
        
        conn.commit()
        
        cursor.execute(f"SELECT observation_ref FROM corrective_actions WHERE id = {q}", (action_id,))
        obs_ref = cursor.fetchone()[0]
        cursor.execute(f"SELECT id FROM observations WHERE reference = {q} AND organization = {q}", (obs_ref, user_org))
        obs_id = cursor.fetchone()[0]
        
        return redirect(url_for("observation_detail", obs_id=obs_id))

    except Exception as e:
        if conn: conn.rollback()
        app.logger.exception("Error editing action")
        return "An internal error occurred.", 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route("/action/<int:action_id>/update", methods=["POST"])
def update_action(action_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user_org = session.get("organization_name", "Unknown")
    user_role = session.get("role_id")
    new_status = request.form.get("status", "").strip()
    completion_notes = request.form.get("completion_notes", "").strip()
    date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if new_status not in ('Open', 'In Progress', 'Completed', 'Verified/Closed'):
        return "Invalid status provided.", 400

    if new_status == "Verified/Closed" and user_role not in (2, 3, 4):
        return "Access Denied: Only Managers or Admins can verify actions.", 403

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        is_postgres = os.environ.get('DATABASE_URL') is not None
        q = "%s" if is_postgres else "?"
        
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT observation_ref, status FROM corrective_actions WHERE id = {q} AND organization = {q}", (action_id, user_org))
        action = cursor.fetchone()

        if not action:
            return "Action not found or unauthorized.", 404

        obs_ref, old_status = action[0], action[1]

        if new_status == "Verified/Closed" and old_status not in ('Completed', 'Verified/Closed'):
            return "Action must be marked 'Completed' before it can be 'Verified/Closed'.", 400

        cursor.execute(f"SELECT id FROM observations WHERE reference = {q} AND organization = {q}", (obs_ref, user_org))
        obs_row = cursor.fetchone()
        if not obs_row:
            return "Associated observation not found.", 404
        actual_obs_id = obs_row[0]

        completed_date = None
        completed_by = None
        verified_by = None
        verified_date = None
        
        if new_status in ("Open", "In Progress"):
            pass 
        elif new_status == "Completed":
            completed_date = date_now
            completed_by = session.get("username")
        elif new_status == "Verified/Closed":
            completed_date = date_now if old_status != 'Verified/Closed' else request.form.get("existing_completed_date", date_now)
            completed_by = session.get("username") if old_status != 'Verified/Closed' else request.form.get("existing_completed_by", session.get("username"))
            verified_by = session.get("username")
            verified_date = date_now if old_status != 'Verified/Closed' else request.form.get("existing_verified_date", date_now)

        cursor.execute(f"""
            UPDATE corrective_actions 
            SET status = {q}, completion_notes = {q}, completed_date = {q}, completed_by = {q}, verified_by = {q}, verified_date = {q}
            WHERE id = {q} AND organization = {q}
        """, (new_status, completion_notes, completed_date, completed_by, verified_by, verified_date, action_id, user_org))
        
        cursor.execute(f"""
            INSERT INTO audit_log (username, action, target_type, target_id, details)
            VALUES ({q}, {q}, {q}, {q}, {q})
        """, (session.get("username"), "UPDATE_ACTION", "CorrectiveAction", str(action_id), f"Status changed from {old_status} to {new_status}"))
        
        conn.commit()
        return redirect(url_for("observation_detail", obs_id=actual_obs_id))

    except Exception as e:
        if conn: conn.rollback()
        app.logger.exception("Error updating corrective action")
        return "An internal database error occurred.", 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

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
