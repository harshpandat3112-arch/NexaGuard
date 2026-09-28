import ipaddress
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlsplit

SUSPICIOUS_WORDS = [
    "login", "verify", "verification", "password", "account",
    "secure", "security", "update", "confirm", "signin",
    "wallet", "payment", "bank", "urgent", "suspended",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
MAX_URL_LENGTH = 2048


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href.strip())


def _extract_urls(text):
    return [match.rstrip(".,);]}") for match in URL_RE.findall(text)]


def _host_is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url):
    original = (url or "").strip()
    if not original:
        raise ValueError("Please enter a URL.")
    if len(original) > MAX_URL_LENGTH:
        raise ValueError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(ord(char) < 32 or char.isspace() for char in original):
        raise ValueError("URL cannot contain spaces or control characters.")

    candidate = original if re.match(r"^[a-z][a-z0-9+.-]*://", original, re.I) else "http://" + original
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        # Accessing port also validates malformed port values.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("That URL is not valid. Check its domain and port.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be scanned.")
    if not host or "." not in host and not _host_is_ip(host):
        raise ValueError("Enter a complete web address, such as example.com.")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain name is not valid.") from exc
    labels = ascii_host.split(".")
    if not _host_is_ip(host) and (len(ascii_host) > 253 or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label, re.I)
        for label in labels
    )):
        raise ValueError("The domain name is not valid.")

    reasons = []
    score = 0
    scheme = parsed.scheme.lower()
    if scheme != "https":
        score += 15
        reasons.append("URL does not use HTTPS")
    if _host_is_ip(host):
        score += 30
        reasons.append("URL uses an IP address instead of a domain")
    if parsed.username is not None or parsed.password is not None:
        score += 30
        reasons.append("URL contains user information that can hide its real destination")
    if ascii_host.startswith("xn--") or ".xn--" in ascii_host:
        score += 25
        reasons.append("Domain contains punycode")
    if host in SHORTENERS:
        score += 20
        reasons.append("URL uses a common shortening service")
    if host.count(".") >= 3:
        score += 10
        reasons.append("Domain has many subdomains")
    if len(original) > 120:
        score += 10
        reasons.append("URL is unusually long")

    path_and_query = f"{parsed.path} {parsed.query} {host}".lower()
    hits = sorted({word for word in SUSPICIOUS_WORDS if word in path_and_query})
    if hits:
        score += min(30, len(hits) * 8)
        reasons.append("Suspicious keywords found: " + ", ".join(hits))

    score = min(score, 100)
    return {
        "score": score,
        "verdict": "SUSPICIOUS" if score >= 40 else "SAFE",
        "reasons": reasons or ["No common phishing indicators detected"],
        "details": {"scheme": scheme, "domain": host, "path": parsed.path or "/"},
    }


def analyze_eml(data):
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        raise ValueError("This email file could not be parsed. Please use a valid .eml file.") from exc

    subject = str(msg.get("subject", "(No subject)"))
    sender = str(msg.get("from", "(Unknown sender)"))
    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            (html_parts if content_type == "text/html" else plain_parts).append(
                content if isinstance(content, str) else str(content)
            )
        except (LookupError, UnicodeError, ValueError):
            continue

    body = "\n".join(plain_parts + html_parts)
    links = []
    for text in plain_parts:
        links.extend(_extract_urls(text))
    for html in html_parts:
        parser = _LinkParser()
        try:
            parser.feed(html)
            links.extend(parser.links)
        except Exception:
            pass
        links.extend(_extract_urls(html))
    combined = f"{subject}\n{sender}\n{body}"
    links.extend(_extract_urls(f"{subject}\n{sender}"))

    unique_urls = list(dict.fromkeys(link for link in links if link.lower().startswith(("http://", "https://"))))
    analyzed_urls = []
    for link in unique_urls[:20]:
        try:
            analyzed_urls.append((link, analyze_url(link)))
        except ValueError:
            continue

    lower_combined = combined.lower()
    keyword_hits = sorted({word for word in SUSPICIOUS_WORDS if word in lower_combined})
    score, reasons = 0, []
    if keyword_hits:
        score += min(35, len(keyword_hits) * 5)
        reasons.append("Suspicious email keywords: " + ", ".join(keyword_hits))
    if "urgent" in lower_combined or "immediately" in lower_combined:
        score += 10
        reasons.append("Message uses urgent language")
    if analyzed_urls:
        max_url_score = max(result["score"] for _, result in analyzed_urls)
        score += min(45, max_url_score)
        if max_url_score >= 40:
            reasons.append("At least one embedded URL looks suspicious")
    if not unique_urls:
        reasons.append("No URLs found in the email")

    score = min(score, 100)
    return {
        "score": score,
        "verdict": "SUSPICIOUS" if score >= 40 else "SAFE",
        "reasons": reasons or ["No common phishing indicators detected"],
        "details": {
            "subject": subject,
            "sender": sender,
            "urls_found": len(unique_urls),
            "ml_text": f"{subject}\n{sender}\n{body[:20000]}\n" + "\n".join(unique_urls[:20]),
        },
        "urls": [
            {"url": url, "score": result["score"], "verdict": result["verdict"]}
            for url, result in analyzed_urls
        ],
    }
