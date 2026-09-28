import os
import sqlite3
from pathlib import Path

from flask import Flask, render_template, request

from analyzer import analyze_eml, analyze_url
from ml_model import predict_text

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["MAX_FORM_MEMORY_SIZE"] = 2 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("NEXAGUARD_DB_PATH", BASE_DIR / "phishlite.db")).resolve()


def get_db():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                ml_verdict TEXT,
                ml_confidence REAL,
                reasons TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_scan(scan_type, target, result, ml):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO scans
            (scan_type, target, verdict, score, ml_verdict, ml_confidence, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_type,
                target[:2048],
                result["verdict"],
                result["score"],
                ml["verdict"],
                ml["confidence"],
                " | ".join(result["reasons"]),
            ),
        )


def render_index(error=None, status=200):
    with get_db() as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 8").fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        suspicious = conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE verdict='SUSPICIOUS'"
        ).fetchone()["n"]
    return render_template(
        "index.html", scans=scans, total=total, suspicious=suspicious, error=error
    ), status


@app.route("/")
def index():
    return render_index()


@app.post("/scan-url")
def scan_url():
    url = request.form.get("url", "").strip()
    try:
        result = analyze_url(url)
    except ValueError as exc:
        return render_index(str(exc), 400)
    ml = predict_text(url)
    save_scan("URL", url, result, ml)
    return render_template(
        "result.html", result=result, ml=ml, scan_type="URL", original=url
    )


@app.post("/scan-eml")
def scan_eml():
    uploaded = request.files.get("eml_file")
    if not uploaded or not uploaded.filename:
        return render_index("Please choose an .eml file.", 400)
    filename = Path(uploaded.filename).name
    if not filename.lower().endswith(".eml"):
        return render_index("Only .eml files are supported.", 400)

    data = uploaded.read()
    if not data:
        return render_index("The selected email file is empty.", 400)
    try:
        result = analyze_eml(data)
    except ValueError as exc:
        return render_index(str(exc), 400)
    ml = predict_text(result["details"].pop("ml_text"))
    save_scan("EMAIL", filename, result, ml)
    return render_template(
        "result.html", result=result, ml=ml, scan_type="EMAIL", original=filename
    )


@app.errorhandler(413)
def too_large(_):
    return render_index("File is too large. Maximum size is 2 MB.", 413)


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"})
