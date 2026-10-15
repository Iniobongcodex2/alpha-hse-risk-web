# ============================================
# ALPHA HSE RISK — WEB APP
# Stage 15.3 — Mobile Login
# ============================================
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import hashlib
from reportlab.platypus.flowables import HRFlowable

app = Flask(__name__)
app.secret_key = "change-this-secret-key-later-2026"   # for session security


# ============================================
# DATABASE PATH — SAME AS DESKTOP
# ============================================
def get_db_path():
    data_folder = os.path.expanduser("~/Documents/ALPHA_HSE_DATA")
    return os.path.join(data_folder, "alpha_hse_risk.db")


# ============================================
# PASSWORD VERIFICATION — SAME AS DESKTOP
# ============================================
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


# ============================================
# HOME — redirect to login or dashboard
# ============================================
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# ============================================
# LOGIN
# ============================================
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
                conn = sqlite3.connect(get_db_path())
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT username, full_name, role_id, is_active, password_hash "
                    "FROM users WHERE username = ?",
                    (username,)
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
                    # SUCCESS — store in session
                    session["username"] = row["username"]
                    session["full_name"] = row["full_name"] or row["username"]
                    session["role_id"] = row["role_id"]
                    return redirect(url_for("dashboard"))

            except Exception as e:
                error = f"Database error: {e}"

    return render_template("login.html", error=error, active=None)


# ============================================
# LOGOUT
# ============================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================
# DASHBOARD
# ============================================
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    stats = {
        "total_assessments": 0,
        "total_hazards": 0,
        "high_critical": 0,
        "recent": []
    }

    try:
        conn = sqlite3.connect(get_db_path())
        conn.row_factory = sqlite3.Row

        # Total assessments
        stats["total_assessments"] = conn.execute(
            "SELECT COUNT(*) AS c FROM assessments"
        ).fetchone()["c"]

        # Total hazards
        stats["total_hazards"] = conn.execute(
            "SELECT COUNT(*) AS c FROM hazards"
        ).fetchone()["c"]

        # High + Critical risks
        stats["high_critical"] = conn.execute(
            "SELECT COUNT(*) AS c FROM hazards WHERE residual_level IN ('High', 'Critical')"
        ).fetchone()["c"]

        # Recent 3 assessments
        rows = conn.execute("""
            SELECT reference, organization, project, date_created
            FROM assessments
            ORDER BY id DESC
            LIMIT 3
        """).fetchall()
        stats["recent"] = [dict(r) for r in rows]

        conn.close()
    except Exception as e:
        pass

    return render_template(
        "dashboard.html",
        active="dashboard",
        username=session.get("username"),
        full_name=session.get("full_name"),
        stats=stats
    )

# ============================================
# NEW ASSESSMENT
# ============================================
# ============================================
# NEW ASSESSMENT
# ============================================
@app.route("/new", methods=["GET", "POST"])
def new_assessment():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Read form data
        organization = request.form.get("organization", "").strip()
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

        # Validate
        if not organization or not hazard_name:
            return render_template("new_assessment.html", active="new",
                                   error="Organization and Hazard Name are required.")

        if not (1 <= severity <= 5) or not (1 <= likelihood <= 5):
            return render_template("new_assessment.html", active="new",
                                   error="Severity and Likelihood must be 1-5.")

        if not (1 <= residual_severity <= 5) or not (1 <= residual_likelihood <= 5):
            return render_template("new_assessment.html", active="new",
                                   error="Residual values must be 1-5.")

        # Calculate risk
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

        # Generate reference
        import datetime
        reference = "HSE-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        date_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            conn = sqlite3.connect(get_db_path())
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO assessments
                (reference, organization, department, location, assessor, project, date_created)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (reference, organization, department, location,
                  session.get("full_name", session.get("username")),
                  project, date_now))

            assessment_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO hazards
                (assessment_id, category, name, severity, likelihood,
                 risk_score, risk_level, existing_controls, additional_controls,
                 residual_severity, residual_likelihood, residual_score,
                 residual_level, action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (assessment_id, category, hazard_name, severity, likelihood,
                  risk_score, risk_level, existing_controls, additional_controls,
                  residual_severity, residual_likelihood, residual_score,
                  residual_level, action))

            conn.commit()
            conn.close()

            return redirect(url_for("history"))

        except Exception as e:
            return render_template("new_assessment.html", active="new",
                                   error=f"Save failed: {e}")

    return render_template("new_assessment.html", active="new")


# ============================================
# RISK LEVEL CALCULATOR (same as desktop)
# ============================================
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


# ============================================
# HISTORY
# ============================================
@app.route("/history")
def history():
    if "username" not in session:
        return redirect(url_for("login"))

    # Load assessments from DB
    assessments = []
    try:
        conn = sqlite3.connect(get_db_path())
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT a.id, a.reference, a.organization, a.project,
                   a.date_created,
                   COUNT(h.id) AS hazard_count
            FROM assessments a
            LEFT JOIN hazards h ON h.assessment_id = a.id
            GROUP BY a.id
            ORDER BY a.id DESC
            LIMIT 50
        """).fetchall()
        assessments = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        assessments = []

    return render_template("history.html", active="history", assessments=assessments)


# ============================================
# ASSESSMENT DETAIL
# ============================================
@app.route("/assessment/<int:assessment_id>")
def assessment_detail(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        with sqlite3.connect(get_db_path()) as conn:
            conn.row_factory = sqlite3.Row

            # Load the assessment
            a_row = conn.execute(
                "SELECT * FROM assessments WHERE id = ?",
                (assessment_id,)
            ).fetchone()

            if a_row is None:
                return redirect(url_for("history"))

            assessment = dict(a_row)

            # Load hazards linked to this assessment
            h_rows = conn.execute(
                """
                SELECT *
                FROM hazards
                WHERE assessment_id = ?
                ORDER BY id
                """,
                (assessment_id,)
            ).fetchall()

            hazards = [dict(row) for row in h_rows]

        return render_template(
            "assessment_detail.html",
            active="history",
            assessment=assessment,
            hazards=hazards
        )

    except sqlite3.Error:
        app.logger.exception("Database error loading assessment %s", assessment_id)
        return "A database error occurred while loading the assessment.", 500

    except Exception:
        app.logger.exception("Unexpected error loading assessment %s", assessment_id)
        return "An unexpected error occurred while loading the assessment.", 500
# ============================================
# PDF DOWNLOAD
# ============================================
@app.route("/assessment/<int:assessment_id>/pdf")
def assessment_pdf(assessment_id):
    if "username" not in session:
        return redirect(url_for("login"))

    from io import BytesIO
    from flask import send_file
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    try:
        conn = sqlite3.connect(get_db_path())
        conn.row_factory = sqlite3.Row

        a_row = conn.execute(
            "SELECT * FROM assessments WHERE id = ?",
            (assessment_id,)
        ).fetchone()

        if a_row is None:
            conn.close()
            return redirect(url_for("history"))

        assessment = dict(a_row)

        h_rows = conn.execute(
            "SELECT * FROM hazards WHERE assessment_id = ? ORDER BY id",
            (assessment_id,)
        ).fetchall()

        hazards = [dict(r) for r in h_rows]
        conn.close()

        # --- Build the PDF ---
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=30, leftMargin=30,
            topMargin=30, bottomMargin=30
        )

        styles = getSampleStyleSheet()
        navy = colors.HexColor("#0F1E3D")
        gold = colors.HexColor("#C9A961")

        title_style = ParagraphStyle(
            "title", parent=styles["Heading1"],
            textColor=gold, fontSize=16, spaceAfter=6
        )
        section_style = ParagraphStyle(
            "section", parent=styles["Heading2"],
            textColor=navy, fontSize=12, spaceAfter=4
        )
        body_style = ParagraphStyle(
            "body", parent=styles["Normal"],
            fontSize=10, leading=13
        )

        elements = []

        # Header
        elements.append(Paragraph("ALPHA HSE RISK ASSESSMENT", title_style))
        elements.append(Paragraph(
            "Professional Risk Management System",
            ParagraphStyle("sub", parent=styles["Normal"], fontSize=9, textColor=colors.grey)
        ))
        elements.append(Spacer(1, 12))

        # Assessment details table
        header_data = [
            ["Reference:", assessment.get("reference") or "—"],
            ["Organization:", assessment.get("organization") or "—"],
            ["Department:", assessment.get("department") or "—"],
            ["Location / Site:", assessment.get("location") or "—"],
            ["Assessor:", assessment.get("assessor") or "—"],
            ["Project:", assessment.get("project") or "—"],
            ["Date:", assessment.get("date_created") or "—"],
        ]
        header_table = Table(header_data, colWidths=[1.5*inch, 5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), navy),
            ('TEXTCOLOR', (0, 0), (0, -1), gold),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 16))

                # Hazards
        for i, h in enumerate(hazards, 1):
            elements.append(Paragraph(
                f"HAZARD {i}: {h.get('category') or '—'}",
                section_style
            ))

            # ---- PART 1: Hazard + Initial Risk + Controls ----
            hazard_part1 = [
                ["Hazard Name:", h.get("name") or "—"],
                ["Severity:", str(h.get("severity") or "—")],
                ["Likelihood:", str(h.get("likelihood") or "—")],
                ["Initial Risk Score:", f"{h.get('risk_score') or 0} ({h.get('risk_level') or '—'})"],
                ["Existing Controls:", h.get("existing_controls") or "—"],
                ["Additional Controls:", h.get("additional_controls") or "—"],
            ]
            t1 = Table(hazard_part1, colWidths=[1.5*inch, 5*inch])
            t1.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t1)

            # ---- SEPARATOR LINE ----
            elements.append(Spacer(1, 4))
            elements.append(HRFlowable(
                width="100%", thickness=0.5,
                color=gold, spaceBefore=2, spaceAfter=6
            ))

            # ---- PART 2: Residual Risk + Action ----
            hazard_part2 = [
                ["Residual Severity:", str(h.get("residual_severity") or "—")],
                ["Residual Likelihood:", str(h.get("residual_likelihood") or "—")],
                ["Residual Risk Score:", f"{h.get('residual_score') or 0} ({h.get('residual_level') or '—'})"],
                ["Action:", h.get("action") or "—"],
            ]
            t2 = Table(hazard_part2, colWidths=[1.5*inch, 5*inch])
            t2.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t2)
            elements.append(Spacer(1, 14))

        

               # Footer
        elements.append(Spacer(1, 16))
        elements.append(HRFlowable(
            width="100%", thickness=0.5,
            color=navy, spaceBefore=2, spaceAfter=8
        ))
        elements.append(Paragraph(
            "SMART SAFETY. STRONG FUTURE.",
            ParagraphStyle("footer", parent=styles["Normal"],
                          fontSize=10, textColor=gold, alignment=1)
        ))

        doc.build(elements)
        buffer.seek(0)

        filename = f"{assessment.get('reference', 'assessment')}.pdf"
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )

    except Exception as e:
        return f"PDF generation failed: {e}"


# ============================================
# PROFILE
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
