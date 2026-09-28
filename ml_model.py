from pathlib import Path
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = Path(__file__).resolve().parent / "phishlite_model.pkl"

TRAINING_DATA = [
    ("https://www.google.com", 0),
    ("https://www.microsoft.com", 0),
    ("https://github.com/login", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.python.org/downloads/", 0),
    ("https://www.amazon.in", 0),
    ("https://www.apple.com", 0),
    ("https://www.cloudflare.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://docs.python.org/3/", 0),
    ("https://accounts.google.com", 0),
    ("https://support.microsoft.com", 0),

    ("http://192.168.1.20/secure/login?verify=1", 1),
    ("http://paypal-login-security.example/verify", 1),
    ("http://secure-account-verify.example/login", 1),
    ("http://bit.ly/verify-account", 1),
    ("http://bank-security.example/update-password", 1),
    ("http://xn--paypa1-9za.example/login", 1),
    ("http://example.com@evil.example/login", 1),
    ("http://urgent-account-suspended.example/confirm", 1),
    ("http://free-prize-winner.example/claim", 1),
    ("http://wallet-security-check.example/verify", 1),
    ("http://payment-confirmation.example/login", 1),
    ("http://signin-verify-now.example/password", 1),
]


def train_model():
    texts = [x[0] for x in TRAINING_DATA]
    labels = [x[1] for x in TRAINING_DATA]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5))),
        ("classifier", LogisticRegression(max_iter=1000)),
    ])
    model.fit(texts, labels)

    with MODEL_PATH.open("wb") as f:
        pickle.dump(model, f)

    return model


def load_model():
    if not MODEL_PATH.exists():
        return train_model()
    with MODEL_PATH.open("rb") as f:
        return pickle.load(f)


MODEL = load_model()


def predict_text(text):
    probabilities = MODEL.predict_proba([text])[0]
    prediction = int(MODEL.predict([text])[0])
    confidence = float(max(probabilities))

    return {
        "verdict": "SUSPICIOUS" if prediction == 1 else "SAFE",
        "confidence": confidence,
    }
