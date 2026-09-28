# NexaGuard — Link & Email Security Workspace

A lightweight security workspace with four practical components:

1. URL detection
2. `.eml` email detection
3. SQLite scan history
4. Machine-learning classification

## Why this project is intentionally simple

It keeps the useful security concepts without turning into a large SOC platform.

### Included
- Flask web app
- SQLite database
- Rule-based phishing checks
- Scikit-learn ML classifier
- `.eml` parser
- Scan history dashboard
- Safe / Suspicious classification
- 0–100 rule score

### Not included
- User authentication
- External threat-intelligence APIs
- VirusTotal
- URL crawling
- Browser automation
- Complex case management
- Production-grade malware analysis

## Setup

```powershell
cd NexaGuard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```

Open `http://127.0.0.1:5000`.

The SQLite database `phishlite.db` is created automatically.

The ML model `phishlite_model.pkl` is created by `train_model.py`. If it is missing, the application trains it automatically on startup.


## Machine learning

The demo uses:

- Character-level TF-IDF
- Logistic Regression

The built-in training examples are intentionally small so the project remains easy to understand. The ML output is an educational signal that can be wrong; its confidence is not calibrated and it must not be treated as a production phishing verdict.

## SQLite data

Each scan stores:

- scan type
- target/file name
- rule verdict
- rule score
- ML verdict
- ML confidence
- reasons
- timestamp

## Safety

The application does **not** open or visit submitted URLs. It analyzes their text and structure locally. These heuristic checks are demonstrations, not a substitute for maintained threat intelligence or a security review.

Debug mode is off by default. Set `FLASK_DEBUG=1` only for local development. The app has no authentication or CSRF protection and is intended for local use; do not expose it directly to the public internet.

