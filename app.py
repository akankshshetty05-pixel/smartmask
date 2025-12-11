import streamlit as st

st.title("SmartMask is Running!")
st.write("If you see this, Streamlit is working correctly.")

import os
import streamlit as st

from celltest import detect_pii, mask_text, read_text_file, read_pdf

# ---------- CONFIG ----------
TEAM_NAME = "Team Uprising"
AI_NAME = "SMARTMASK"

st.set_page_config(
    page_title=f"{AI_NAME} – PII Protection",
    page_icon="🔐",
    layout="wide"
)

# Small CSS for nicer look (optional)
st.markdown(
    """
    <style>
    .main {
        background-color: #0f172a;
        color: #e5e7eb;
    }
    .stTextArea textarea, .stTextInput input {
        color: #e5e7eb !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ---------- SIDEBAR ----------
with st.sidebar:
    st.markdown(
        "<h3 style='color:#38bdf8;'>SMARTMASK Controls</h3>",
        unsafe_allow_html=True
    )
    st.markdown("AI‑assisted masking for sensitive data in documents.")

    st.markdown("**Supports:**")
    st.markdown(
        "- ✅ Aadhaar\n"
        "- ✅ PAN\n"
        "- ✅ Phone\n"
        "- ✅ Email\n"
        "- ✅ Names (AI)\n"
        "- ✅ Locations (AI)"
    )

    auto_mask_high_conf = st.checkbox(
        "Auto‑mask high confidence items (≥ 0.90)",
        value=True
    )

    st.markdown("---")
    st.markdown("**How it works:**")
    st.markdown(
        "1. Upload a `.txt` or `.pdf` file\n"
        "2. SMARTMASK detects PII using regex + spaCy\n"
        "3. Review & choose what to mask\n"
        "4. Download a safe, masked version"
    )

# ---------- HEADER BANNER ----------
st.markdown(
    f"""
    <div style="
        padding: 0.9rem 1.2rem;
        border-radius: 0.9rem;
        background: linear-gradient(90deg, #1d4ed8, #22c55e);
        color: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.8rem;
    ">
        <div style="font-size: 1.1rem; font-weight: 600;">
            🤖 {AI_NAME} (AI) · PII Protection
        </div>
        <div style="font-size: 0.9rem;">
            👨‍💻 {TEAM_NAME}
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.title("Document Privacy Dashboard")
st.caption("Hybrid AI (spaCy) + regex rules for masking sensitive data in text & PDF files.")

# ---------- FILE UPLOAD ----------
st.markdown("### 1️⃣ Upload your document")

uploaded_file = st.file_uploader(
    "Choose a .txt or .pdf file",
    type=["txt", "pdf"],
    help="Your file is processed locally and not stored permanently."
)

if uploaded_file is None:
    st.info("👆 Upload a file to get started.")
else:
    # ---------- SAVE TEMP FILE ----------
    os.makedirs("uploads", exist_ok=True)
    temp_path = os.path.join("uploads", uploaded_file.name)

    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # ---------- READ TEXT ----------
    if uploaded_file.name.lower().endswith(".txt"):
        text = read_text_file(temp_path)
        file_type_label = "Text file"
    else:
        text = read_pdf(temp_path)
        file_type_label = "PDF file"

    # Clean up temp file (we already have the text)
    try:
        os.remove(temp_path)
    except OSError:
        pass

    # ---------- ORIGINAL PREVIEW & SUMMARY ----------
    st.markdown("### 2️⃣ Original content preview")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown(f"**File type:** {file_type_label}")
        st.text_area(
            "Original document (first 600 characters)",
            text[:600],
            height=250
        )

    pii_items = detect_pii(text)

    with col2:
        st.markdown("**Detection summary**")
        if not pii_items:
            st.success("No PII detected ✅")
        else:
            counts = {}
            for item in pii_items:
                t = item.get("type", "UNKNOWN")
                counts[t] = counts.get(t, 0) + 1

            for pii_type, count in counts.items():
                st.markdown(f"- **{pii_type}**: {count}")

    # ---------- REVIEW DETECTIONS ----------
    st.markdown("### 3️⃣ Review detected PII")

    if not pii_items:
        st.info("No sensitive information found. You're good to go ✅")
    else:
        selected_items = []
        st.write("Tick the items you want to mask:")

        for i, item in enumerate(pii_items):
            pii_type = item.get("type", "UNKNOWN")
            value = item.get("value", "")
            confidence = float(item.get("confidence", 0.0))

            # Currently all items are pre‑checked
            default_checked = True
            if auto_mask_high_conf and confidence < 0.90:
                # You can tweak this behaviour later if needed
                default_checked = True

            label = f"{pii_type} | {value} | conf={confidence:.2f}"

            if st.checkbox(label, value=default_checked, key=f"pii_{i}"):
                selected_items.append(item)

        # ---------- MASK & DOWNLOAD ----------
        st.markdown("### 4️⃣ Mask & download")

        if st.button("🔒 Apply masking"):
            if not selected_items:
                st.warning("No items selected for masking.")
            else:
                masked_text = mask_text(text, selected_items)

                st.success("Masking applied successfully ✅")

                st.subheader("Masked document preview")
                st.text_area(
                    "Masked content (first 600 characters)",
                    masked_text[:600],
                    height=250
                )

                st.download_button(
                    "⬇ Download full masked document",
                    masked_text,
                    file_name="smartmask_output.txt"
                )
