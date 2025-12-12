import re
import pdfplumber
import spacy

# Load spaCy English model (make sure `en_core_web_sm` is installed)
import subprocess
import sys
import spacy

MODEL_NAME = "en_core_web_sm"
try:
    nlp = spacy.load(MODEL_NAME)
except OSError:
    try:
        # Download model at runtime (safe fallback on Streamlit Cloud)
        subprocess.check_call([sys.executable, "-m", "spacy", "download", MODEL_NAME])
        nlp = spacy.load(MODEL_NAME)
    except Exception as e:
        raise RuntimeError("Failed to load or download spaCy model en_core_web_sm: " + str(e))


# ---------- FILE READERS ----------

def read_text_file(file_path: str) -> str:
    """Read plain text file and return content as string."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def read_pdf(file_path: str) -> str:
    """Read PDF using pdfplumber and return extracted text."""
    text = ""
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text


# ---------- REGEX PATTERNS (RULE-BASED PII) ----------

aadhaar_pattern = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")
pan_pattern = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
phone_pattern = re.compile(r"\b[6-9]\d{9}\b")
email_pattern = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"
)


# ---------- PII DETECTION (RULES) ----------

def detect_pii_rules(text: str):
    """
    Rule-based PII detection using regex patterns.
    Returns list of dicts: {type, value, confidence, source}
    """
    results = []

    for m in aadhaar_pattern.finditer(text):
        results.append({
            "type": "AADHAAR",
            "value": m.group(),
            "confidence": 0.98,
            "source": "rule"
        })

    for m in pan_pattern.finditer(text):
        results.append({
            "type": "PAN",
            "value": m.group(),
            "confidence": 0.97,
            "source": "rule"
        })

    for m in phone_pattern.finditer(text):
        results.append({
            "type": "PHONE",
            "value": m.group(),
            "confidence": 0.95,
            "source": "rule"
        })

    for m in email_pattern.finditer(text):
        results.append({
            "type": "EMAIL",
            "value": m.group(),
            "confidence": 0.95,
            "source": "rule"
        })

    return results


# ---------- PII DETECTION (AI - spaCy NER) ----------

def detect_pii_ml(text: str):
    """
    AI-based PII detection using spaCy NER.
    Detects PERSON as NAME and GPE/LOC as ADDRESS.
    """
    results = []
    doc = nlp(text)

    for ent in doc.ents:
        if ent.label_ == "PERSON":
            results.append({
                "type": "NAME",
                "value": ent.text,
                "confidence": 0.75,
                "source": "ml"
            })
        elif ent.label_ in ("GPE", "LOC"):
            results.append({
                "type": "ADDRESS",
                "value": ent.text,
                "confidence": 0.70,
                "source": "ml"
            })

    return results


# ---------- COMBINED DETECTOR ----------

def detect_pii(text: str):
    """
    Hybrid PII detection:
    - Rule-based regex for Aadhaar, PAN, Phone, Email
    - AI-based spaCy NER for Name & Address
    """
    results = []

    # Rule-based detections
    rule_hits = detect_pii_rules(text)
    results.extend(rule_hits)

    # ML-based detections
    ml_hits = detect_pii_ml(text)
    results.extend(ml_hits)

    return results


# ---------- MASKING LOGIC ----------

def mask_value(value: str, pii_type: str) -> str:
    """Return masked version of a PII value based on its type."""
    if pii_type == "AADHAAR":
        # Keep last 4 digits
        return "XXXX XXXX " + value[-4:]

    if pii_type == "PAN":
        # Mask first 7 chars
        return "XXXXX" + value[-3:]

    if pii_type == "PHONE":
        # Mask first 6 digits
        return "XXXXXX" + value[-4:]

    if pii_type == "EMAIL":
        # Keep domain, mask username
        parts = value.split("@")
        if len(parts) == 2:
            return "xxxxx@" + parts[1]
        return "[REDACTED EMAIL]"

    if pii_type in ("NAME", "ADDRESS"):
        return f"[REDACTED {pii_type}]"

    return "[REDACTED]"


def mask_text(text: str, pii_items):
    """
    Replace all occurrences of detected PII values in text
    with their masked versions.
    """
    masked_text = text
    # Simple replacement – for more complex cases we could do index-based masking
    # but this is sufficient for typical documents.
    for item in pii_items:
        value = item.get("value", "")
        pii_type = item.get("type", "UNKNOWN")
        if value:
            masked_text = masked_text.replace(
                value,
                mask_value(value, pii_type)
            )
    return masked_text


# ---------- LOCAL TEST (OPTIONAL) ----------

if __name__ == "__main__":
    # Simple test text (for terminal testing only)
    sample_text = """
    Name: Akanksh Shetty
    Lives in Tumkur, Karnataka.
    Aadhaar: 1234 5678 9012
    PAN: ABCDE1234F
    Phone: 9876543210
    Email: akanksh@example.com
    """

    print("=== SMARTMASK v4 TEST (Hybrid Rules + AI) ===")
    items = detect_pii(sample_text)

    for item in items:
        print(item)

    print("\n--- MASKED OUTPUT ---")
    print(mask_text(sample_text, items))

