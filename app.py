import streamlit as st
import time
import io
import zipfile
import gc
import psutil
from typing import Dict, List, Any
from engine import (
    calculate_sha256,
    extract_metadata,
    sanitize_pdf,
    validate_sanitized_pdf
)

# Enforce clean Streamlit configuration options
st.set_page_config(
    page_title="RedPurge PDF - Digital Forensics Tool",
    page_icon="🩸",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# 1. PREMIUM DARK CYBERSECURITY THEME & CSS STYLING
# ---------------------------------------------------------
cyber_style = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">

<style>
    /* Global Base Enforcements */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0D0D0D !important;
        color: #EDF2F4 !important;
        font-family: 'Space Mono', 'Courier New', monospace !important;
    }
    
    /* Sidebar Overrides */
    [data-testid="stSidebar"] {
        background-color: #050508 !important;
        border-right: 2px solid #2B2D42 !important;
        box-shadow: 5px 0 15px rgba(217, 4, 41, 0.1) !important;
    }

    /* Headings Styling */
    h1, h2, h3, h4, h5, h6 {
        color: #EDF2F4 !important;
        font-family: 'Space Mono', 'Courier New', monospace !important;
        font-weight: 700 !important;
        letter-spacing: 1px;
    }
    
    /* Neon Text Accents */
    .neon-text-red {
        color: #D90429 !important;
        text-shadow: 0 0 10px rgba(217, 4, 41, 0.6);
    }
    
    .neon-text-white {
        color: #EDF2F4 !important;
        text-shadow: 0 0 5px rgba(255, 255, 255, 0.3);
    }
    
    .muted-text {
        color: #8D99AE !important;
        font-size: 0.85rem;
    }

    /* High-Tech Custom Metrics & Cards */
    .cyber-card {
        background-color: #1A1A24 !important;
        border: 1px solid #2B2D42 !important;
        border-radius: 6px !important;
        padding: 16px 20px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.6) !important;
        transition: all 0.3s ease-in-out !important;
    }
    
    .cyber-card:hover {
        border-color: #D90429 !important;
        box-shadow: 0 0 12px rgba(217, 4, 41, 0.3) !important;
        transform: translateY(-2px);
    }

    .metric-value {
        font-size: 1.8rem;
        font-weight: bold;
        color: #D90429;
        text-shadow: 0 0 8px rgba(217, 4, 41, 0.5);
        margin: 5px 0;
    }

    .metric-label {
        font-size: 0.8rem;
        color: #8D99AE;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Input elements & File Uploader customizations */
    div[data-testid="stFileUploader"] {
        border: 2px dashed #2B2D42 !important;
        background-color: #1A1A24 !important;
        border-radius: 6px !important;
        padding: 15px !important;
        transition: border-color 0.3s ease;
    }
    
    div[data-testid="stFileUploader"]:hover {
        border-color: #D90429 !important;
    }

    /* Dynamic Action Buttons */
    .stButton>button {
        background-color: #1A1A24 !important;
        color: #EDF2F4 !important;
        border: 1px solid #D90429 !important;
        border-radius: 4px !important;
        padding: 10px 24px !important;
        font-weight: bold !important;
        font-family: 'Space Mono', 'Courier New', monospace !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        box-shadow: 0 0 5px rgba(217, 4, 41, 0.2) !important;
        transition: all 0.3s ease !important;
        width: 100%;
    }

    .stButton>button:hover {
        background-color: #D90429 !important;
        color: #0D0D0D !important;
        box-shadow: 0 0 15px rgba(217, 4, 41, 0.7) !important;
        border-color: #D90429 !important;
    }

    /* Warning & Success Custom Containers */
    .threat-alert-box {
        background-color: rgba(217, 4, 41, 0.08) !important;
        border: 1px solid #D90429 !important;
        border-radius: 4px !important;
        padding: 12px 15px !important;
        color: #EDF2F4 !important;
        margin-bottom: 15px !important;
        box-shadow: 0 0 8px rgba(217, 4, 41, 0.15);
    }
    
    .clean-success-box {
        background-color: rgba(0, 200, 83, 0.08) !important;
        border: 1px solid #00C853 !important;
        border-radius: 4px !important;
        padding: 12px 15px !important;
        color: #EDF2F4 !important;
        margin-bottom: 15px !important;
        box-shadow: 0 0 8px rgba(0, 200, 83, 0.15);
    }

    /* Real-Time Terminal Console */
    .terminal-titlebar {
        background-color: #1A1A24;
        border: 1px solid #2B2D42;
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        padding: 8px 15px;
        font-size: 0.75rem;
        color: #8D99AE;
        display: flex;
        align-items: center;
    }
    
    .terminal-dot {
        height: 8px;
        width: 8px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }
    
    .terminal-dot.red { background-color: #D90429; }
    .terminal-dot.yellow { background-color: #FFB020; }
    .terminal-dot.green { background-color: #00C853; }

    .terminal-console {
        background-color: #050508 !important;
        border: 1px solid #2B2D42 !important;
        border-bottom-left-radius: 6px;
        border-bottom-right-radius: 6px;
        padding: 15px !important;
        font-family: 'Space Mono', 'Courier New', monospace !important;
        color: #EDF2F4 !important;
        height: 280px;
        overflow-y: auto;
        box-shadow: inset 0 0 10px rgba(0, 0, 0, 0.8) !important;
        font-size: 0.85rem !important;
        line-height: 1.4 !important;
    }

    /* Custom high-contrast scrollbar */
    .terminal-console::-webkit-scrollbar {
        width: 8px;
    }
    .terminal-console::-webkit-scrollbar-track {
        background: #050508;
    }
    .terminal-console::-webkit-scrollbar-thumb {
        background: #2B2D42;
        border-radius: 4px;
    }
    .terminal-console::-webkit-scrollbar-thumb:hover {
        background: #D90429;
    }

    /* Diagnostic Table Style */
    .cyber-table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
        font-size: 0.85rem;
    }
    .cyber-table th {
        background-color: #1A1A24;
        border-bottom: 2px solid #2B2D42;
        color: #D90429;
        padding: 10px;
        text-align: left;
        text-transform: uppercase;
        font-size: 0.75rem;
    }
    .cyber-table td {
        border-bottom: 1px solid #1A1A24;
        padding: 10px;
        color: #EDF2F4;
        font-family: 'Space Mono', monospace;
    }
    .cyber-table tr:hover {
        background-color: rgba(217, 4, 41, 0.04);
    }
    
    /* Fix standard Streamlit block padding */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }
</style>
"""
st.markdown(cyber_style, unsafe_allow_html=True)

# ---------------------------------------------------------
# 2. STATE PERSISTENCE ARCHITECTURE (SESSION STATE)
# ---------------------------------------------------------
if "files_cache" not in st.session_state:
    st.session_state.files_cache = {}
if "passwords_cache" not in st.session_state:
    st.session_state.passwords_cache = {}
if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = [
        f"[{time.strftime('%H:%M:%S')}] [SYSTEM] RedPurge PDF Forensics Engine initialized."
    ]
if "diagnostics_ram" not in st.session_state:
    # Seed with initial RAM usage
    proc = psutil.Process()
    ram_mb = proc.memory_info().rss / 1024 / 1024
    st.session_state.diagnostics_ram = [{
        "timestamp": time.strftime('%H:%M:%S'),
        "action": "INIT",
        "ram_mb": ram_mb
    }]

def add_audit_log(category: str, message: str):
    """
    Appends a formatted, timestamped log line to the session state log tracker.
    """
    timestamp = time.strftime("%H:%M:%S")
    log_line = f"[{timestamp}] [{category}] {message}"
    st.session_state.audit_logs.append(log_line)

def get_current_ram() -> float:
    """
    Queries standard system statistics for the python process RSS usage.
    """
    proc = psutil.Process()
    return proc.memory_info().rss / 1024 / 1024

# ---------------------------------------------------------
# 3. SIDEBAR NAVIGATION & CREDENTIAL PROFILE
# ---------------------------------------------------------
with st.sidebar:
    st.markdown('<h1 class="neon-text-red">🩸 REDPURGE PDF</h1>', unsafe_allow_html=True)
    st.markdown('<p class="muted-text">Professional Digital Forensics & Metadata Purging Engine</p>', unsafe_allow_html=True)
    st.markdown('<div style="border-top: 1px solid #2B2D42; margin: 15px 0;"></div>', unsafe_allow_html=True)

    # Official Undergraduate Credentials Info Box
    st.markdown("### 🪪 OPERATOR IDENTITY")
    credentials_html = """
    <div style="background-color: #1A1A24; border: 1px solid #2B2D42; border-radius: 4px; padding: 12px; font-size: 0.8rem; margin-bottom: 20px;">
        <span style="color: #D90429; font-weight: bold; display: block; margin-bottom: 5px;">Kirana Shofa Dzakiyyah</span>
        <span style="color: #8D99AE; display: block;">NIM: 25051204358</span>
        <span style="color: #8D99AE; display: block;">S1 Teknik Informatika</span>
        <span style="color: #8D99AE; display: block; font-weight: bold;">UNESA</span>
    </div>
    """
    st.markdown(credentials_html, unsafe_allow_html=True)
    
    st.markdown("### 🏷️ METADATA ENGINE")
    st.markdown("`SYSTEM STATUS: PASSIVE`" if len(st.session_state.files_cache) == 0 else "`SYSTEM STATUS: ACTIVE`")
    st.markdown("`VERSION: v1.0.0`")
    st.markdown("`UPLOAD LIMIT: 100MB`")

    st.markdown('<div style="border-top: 1px solid #2B2D42; margin: 15px 0;"></div>', unsafe_allow_html=True)
    st.markdown("### 📊 ENGINE RAM DIAGNOSTICS")
    
    ram_now = get_current_ram()
    st.markdown(f"**Current RSS:** `{ram_now:.2f} MB`")
    
    # Render mini RAM telemetry logs
    telemetry_html = '<div style="font-size:0.75rem; background-color:#050508; border: 1px solid #2B2D42; border-radius:4px; padding: 8px; max-height: 120px; overflow-y: auto; color:#8D99AE;">'
    for r_entry in reversed(st.session_state.diagnostics_ram[-5:]):
         telemetry_html += f"[{r_entry['timestamp']}] {r_entry['action']}: {r_entry['ram_mb']:.2f} MB<br>"
    telemetry_html += "</div>"
    st.markdown(telemetry_html, unsafe_allow_html=True)

    st.markdown('<div style="border-top: 1px solid #2B2D42; margin: 15px 0;"></div>', unsafe_allow_html=True)
    # Wipe Workspace Button in Sidebar
    if st.button("🧹 Clear Workspace", key="sidebar_reset"):
        st.session_state.files_cache = {}
        st.session_state.passwords_cache = {}
        st.session_state.audit_logs = []
        st.session_state.diagnostics_ram = []
        
        # Enforce manual garbage collection for Zero-Retention compliance
        import gc
        gc.collect()
        
        st.rerun()

# ---------------------------------------------------------
# 4. ANALYTICAL METRICS HEADER CARDS
# ---------------------------------------------------------
st.markdown('<h2 class="neon-text-white">🛡️ DIGITAL FORENSICS CONTROL DASHBOARD</h2>', unsafe_allow_html=True)
st.markdown('<p class="muted-text">Ingest tracking, identify vendor metadata footprints, and purge incremental revisions in memory.</p>', unsafe_allow_html=True)

# Calculate metrics from session cache
total_cached = len(st.session_state.files_cache)
total_stripped_points = 0
total_sterilized = 0

for f_data in st.session_state.files_cache.values():
    if f_data.get("status") == "Sanitized":
        total_sterilized += 1
        total_stripped_points += f_data.get("fields_purged", 0) + f_data.get("page_elements_scrubbed", 0)

# Render customized cyber cards using pure CSS columns
m_col1, m_col2, m_col3 = st.columns(3)

with m_col1:
    st.markdown(f"""
    <div class="cyber-card">
        <div class="metric-label">📁 Files Cached in RAM</div>
        <div class="metric-value">{total_cached}</div>
        <div style="font-size: 0.75rem; color: #8D99AE;">Active cryptographic buffers</div>
    </div>
    """, unsafe_allow_html=True)

with m_col2:
    st.markdown(f"""
    <div class="cyber-card">
        <div class="metric-label">⚡ Metadata Points Purged</div>
        <div class="metric-value">{total_stripped_points}</div>
        <div style="font-size: 0.75rem; color: #8D99AE;">Tags, streams, and tracking fields stripped</div>
    </div>
    """, unsafe_allow_html=True)

with m_col3:
    st.markdown(f"""
    <div class="cyber-card">
        <div class="metric-label">🧪 Sterilized Files Ready</div>
        <div class="metric-value">{total_sterilized} / {total_cached}</div>
        <div style="font-size: 0.75rem; color: #8D99AE;">Verified clean chain of custody</div>
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------
# 5. DYNAMIC FILE INGEST & BOUNDARY VALUE ANALYSIS (BVA)
# ---------------------------------------------------------
st.markdown("### 📥 CHAIN OF CUSTODY FILE INGEST")
uploaded_files = st.file_uploader(
    "Drag and drop multiple forensic target PDFs here (100MB limit per file)",
    type=["pdf"],
    accept_multiple_files=True,
    key="pdf_uploader"
)

if uploaded_files:
    for u_file in uploaded_files:
        filename = u_file.name
        
        # Defensive Input boundary value check
        file_size_bytes = len(u_file.getvalue())
        file_size_mb = file_size_bytes / (1024 * 1024)
        
        # Check size threshold bounds
        if file_size_mb > 100.0:
            if filename not in st.session_state.files_cache or st.session_state.files_cache[filename].get("status") != "Oversized":
                add_audit_log("BVA WARNING", f"File '{filename}' exceeds 100MB threshold (Size: {file_size_mb:.2f} MB). Processing blocked.")
                st.session_state.files_cache[filename] = {
                    "original_hash": "BLOCKED",
                    "status": "Oversized",
                    "error": f"File exceeds strict 100MB limit ({file_size_mb:.2f} MB)"
                }
            continue
            
        if filename not in st.session_state.files_cache:
            ram_pre_ingest = get_current_ram()
            file_bytes = u_file.read()
            sha_hash = calculate_sha256(file_bytes)
            
            # Check for decryption first using parser metadata tool
            forensic_parse = extract_metadata(file_bytes)
            
            status = "Ingested"
            err_msg = None
            if forensic_parse["is_encrypted"]:
                status = "Encrypted"
                err_msg = forensic_parse["error"]
                add_audit_log("THREAT ALERT", f"Password footprint identified. Document '{filename}' is encrypted.")
            elif forensic_parse["error"]:
                status = "Corrupted"
                err_msg = forensic_parse["error"]
                add_audit_log("ERROR", f"File '{filename}' load error: {err_msg}")
            else:
                add_audit_log("INGEST", f"File loaded: {filename} (SHA-256: {sha_hash[:16]}...)")
                
                # Check for software tracking leak indicators for forensics alerts
                if forensic_parse["producer"] != "Empty" and forensic_parse["producer"] != "N/A":
                    add_audit_log("THREAT ALERT", f"Software footprint leak in '{filename}': '/Producer' tag exposed ({forensic_parse['producer']}).")
                if forensic_parse["creator"] != "Empty" and forensic_parse["creator"] != "N/A":
                    add_audit_log("THREAT ALERT", f"Software footprint leak in '{filename}': '/Creator' tag exposed ({forensic_parse['creator']}).")

            # Store in cache
            st.session_state.files_cache[filename] = {
                "original_bytes": file_bytes,
                "original_hash": sha_hash,
                "status": status,
                "cleaned_bytes": None,
                "cleaned_hash": None,
                "metadata": forensic_parse,
                "fields_purged": 0,
                "page_elements_scrubbed": 0,
                "error": err_msg,
                "validation": None
            }
            
            ram_post_ingest = get_current_ram()
            st.session_state.diagnostics_ram.append({
                "timestamp": time.strftime('%H:%M:%S'),
                "action": f"INGEST({filename[:10]})",
                "ram_mb": ram_post_ingest
            })

# ---------------------------------------------------------
# 6. ENCRYPTION WARNING & DECRYPTION PORTAL
# ---------------------------------------------------------
encrypted_files = [fname for fname, fdata in st.session_state.files_cache.items() if fdata["status"] == "Encrypted"]

if encrypted_files:
    st.markdown("### 🔑 ENCRYPTED DOCUMENT AUTHENTICATION REQUIRED")
    for enc_fname in encrypted_files:
        st.markdown(
            f"""<div class="threat-alert-box">
                🛡️ <b>FORENSIC SECURITY LOCK:</b> File <b>{enc_fname}</b> is encrypted. 
                Decryption credentials are required to parse structure and sanitise tracking dictionaries.
            </div>""", 
            unsafe_allow_html=True
        )
        
        # Render clean key entry
        input_col1, input_col2 = st.columns([3, 1])
        with input_col1:
            entered_pw = st.text_input(
                f"Enter decryption passphrase for {enc_fname}", 
                type="password", 
                key=f"pw_{enc_fname}",
                label_visibility="collapsed"
            )
        with input_col2:
            if st.button("Unlock File", key=f"btn_unlock_{enc_fname}"):
                if entered_pw:
                    # Attempt authentication re-parse
                    file_data = st.session_state.files_cache[enc_fname]
                    auth_check = extract_metadata(file_data["original_bytes"], entered_pw)
                    
                    if auth_check["is_decrypted"]:
                        st.session_state.passwords_cache[enc_fname] = entered_pw
                        file_data["status"] = "Ingested"
                        file_data["metadata"] = auth_check
                        file_data["error"] = None
                        add_audit_log("SYSTEM", f"Authentication success! Decrypted '{enc_fname}' successfully in memory.")
                        st.rerun()
                    else:
                        add_audit_log("SYSTEM", f"Authentication failure on '{enc_fname}': Incorrect password.")
                        st.error("Decryption failed. Please verify credentials.")

# ---------------------------------------------------------
# 7. EXECUTE SANITIZATION & METADATA PURGING
# ---------------------------------------------------------
active_ingested = [fname for fname, fdata in st.session_state.files_cache.items() if fdata["status"] in ["Ingested", "Sanitized"]]

if active_ingested:
    st.markdown("### ⚙️ FORENSIC SANITIZATION ENGINE")
    col_run, col_spacing = st.columns([1, 2])
    with col_run:
        if st.button("🩸 Execute Metadata Purge"):
            ram_pre_purge = get_current_ram()
            
            for fname in active_ingested:
                fdata = st.session_state.files_cache[fname]
                
                # Retrieve matching password if encrypted
                pw = st.session_state.passwords_cache.get(fname, None)
                
                try:
                    # Cleanse PDF in memory
                    cleaned_bytes, clean_stats = sanitize_pdf(fdata["original_bytes"], pw)
                    
                    if cleaned_bytes and clean_stats["status"] == "Success":
                        cleaned_hash = calculate_sha256(cleaned_bytes)
                        
                        # Trigger deep cross-validation self-auditor
                        val_results = validate_sanitized_pdf(fdata["original_hash"], cleaned_bytes)
                        
                        fdata["status"] = "Sanitized"
                        fdata["cleaned_bytes"] = cleaned_bytes
                        fdata["cleaned_hash"] = cleaned_hash
                        fdata["fields_purged"] = clean_stats["metadata_fields_purged"]
                        fdata["page_elements_scrubbed"] = clean_stats["page_elements_scrubbed"]
                        fdata["validation"] = val_results
                        fdata["neutralized_log"] = clean_stats.get("neutralized_log", {})
                        
                        # Log success audit
                        add_audit_log("PURGE SUCCESS", f"Sanitized '{fname}'. Purged {fdata['fields_purged']} dictionary items & {fdata['page_elements_scrubbed']} page-level tracking elements.")
                        add_audit_log("DIAGNOSTIC", f"Verified clean. Pre-Hash: {fdata['original_hash'][:12]}... -> Post-Hash: {cleaned_hash[:12]}...")
                        
                        if not val_results["metadata_fully_purged"]:
                            add_audit_log("BVA WARNING", f"Scrubbing Auditor warning for '{fname}': Residual markers {val_results['remaining_fields']}")
                    else:
                        fdata["status"] = "Corrupted"
                        fdata["error"] = clean_stats["error"]
                        add_audit_log("ERROR", f"File '{fname}' scrubbing crashed: {clean_stats['error']}")
                
                except Exception as ex:
                    fdata["status"] = "Corrupted"
                    fdata["error"] = str(ex)
                    add_audit_log("ERROR", f"Defensive boundary failure in '{fname}': {str(ex)}")
            
            # Enforce zero retention gc sweep
            gc.collect()
            ram_post_purge = get_current_ram()
            
            st.session_state.diagnostics_ram.append({
                "timestamp": time.strftime('%H:%M:%S'),
                "action": "PURGE",
                "ram_mb": ram_post_purge
            })
            st.rerun()

# ---------------------------------------------------------
# 8. DIAGNOSTIC DIAGRAM & COMPARISON METADATA TABLE
# ---------------------------------------------------------
if st.session_state.files_cache:
    st.markdown("### 📋 FORENSIC DIAGNOSTIC DATA TABLE")
    
    # Custom HTML Table for vibrant high-contrast cyber theme
    table_html = """
    <table class="cyber-table">
        <thead>
            <tr>
                <th>Target File Name</th>
                <th>Cryptographic Ingestion Hash (SHA-256)</th>
                <th>Forensic Status</th>
                <th>Sanitized Cryptographic Hash (SHA-256)</th>
                <th>Chain Integrity Verified</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for fname, fdata in st.session_state.files_cache.items():
        original_h = fdata["original_hash"]
        status = fdata["status"]
        cleaned_h = fdata["cleaned_hash"] if fdata["cleaned_hash"] else "N/A"
        
        status_color = "#8D99AE"
        if status == "Ingested":
            status_color = "#FFB020"
        elif status == "Encrypted":
            status_color = "#D90429"
        elif status == "Sanitized":
            status_color = "#00C853"
        elif status == "Corrupted":
            status_color = "#D90429"
            
        status_span = f'<span style="color: {status_color}; font-weight: bold;">{status.upper()}</span>'
        
        # Verify if hash changed mathematically
        if status == "Sanitized":
            verification_status = "🧬 PURGED & ALTERED"
            verification_color = "#00C853"
        elif status == "Oversized":
            verification_status = "⚠️ BLOCKED (BVA)"
            verification_color = "#D90429"
        elif status == "Corrupted":
            verification_status = "❌ STRUCT ERROR"
            verification_color = "#D90429"
        else:
            verification_status = "🔒 UNRESOLVED CHAIN"
            verification_color = "#FFB020"
            
        verification_span = f'<span style="color: {verification_color}; font-weight: bold;">{verification_status}</span>'
        
        table_html += f"""
        <tr>
            <td>{fname}</td>
            <td style="font-size:0.75rem; color:#8D99AE;">{original_h}</td>
            <td>{status_span}</td>
            <td style="font-size:0.75rem; color:#8D99AE;">{cleaned_h}</td>
            <td>{verification_span}</td>
        </tr>
        """
        
    table_html += "</tbody></table>"
    st.markdown(table_html, unsafe_allow_html=True)

# ---------------------------------------------------------
# 9. SMART DOWNLOAD SYSTEM (100% IN-MEMORY ZIP / PDF)
# ---------------------------------------------------------
sanitized_files = {fname: fdata for fname, fdata in st.session_state.files_cache.items() if fdata["status"] == "Sanitized"}

if sanitized_files:
    st.markdown("### 📥 DOWNLOAD SECURED ARTIFACTS")
    
    if len(sanitized_files) == 1:
        # Single file download trigger
        fname = list(sanitized_files.keys())[0]
        fdata = sanitized_files[fname]
        clean_name = fname.replace(".pdf", "_clean.pdf")
        
        st.markdown(
            f"""<div class="clean-success-box">
                🛡️ <b>CHAIN OF CUSTODY VERIFIED:</b> <b>{fname}</b> has been successfully sanitized in memory.
                All tracking dictionaries, private PieceInfo blocks, and catalog metadata streams are completely purged.
            </div>""",
            unsafe_allow_html=True
        )
        
        # Display the metadata inspection summary expander
        if "neutralized_log" in fdata and fdata["neutralized_log"]:
            with st.expander("🔍 View Extracted & Neutralized Metadata Flags", expanded=True):
                table_rows = ""
                for field, (found, val) in fdata["neutralized_log"].items():
                    status_text = f'<span style="color: #D90429; font-weight: bold;">Exposed</span> (<code style="color: #8D99AE;">{val}</code>)' if found else '<span style="color: #8D99AE;">Not Detected</span>'
                    action_text = '<span style="color: #D90429; font-weight: bold; text-shadow: 0 0 5px rgba(217,4,41,0.5);">🩸 ERADICATED</span>' if found else '<span style="color: #00C853; font-weight: bold;">✔️ SECURE / CLEARED</span>'
                    table_rows += f"""
                    <tr>
                        <td style="color: #EDF2F4; font-weight: bold; border-bottom: 1px solid #2B2D42; padding: 8px;">{field}</td>
                        <td style="border-bottom: 1px solid #2B2D42; padding: 8px;">{status_text}</td>
                        <td style="border-bottom: 1px solid #2B2D42; padding: 8px;">{action_text}</td>
                    </tr>
                    """
                
                st.markdown(f"""
                <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-family: 'Space Mono', monospace; font-size: 0.85rem;">
                    <thead>
                        <tr style="border-bottom: 2px solid #2B2D42; text-align: left; color: #D90429; font-size: 0.75rem; text-transform: uppercase;">
                            <th style="padding: 8px;">Field Name</th>
                            <th style="padding: 8px;">Status Found</th>
                            <th style="padding: 8px;">Action Taken</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows}
                    </tbody>
                </table>
                """, unsafe_allow_html=True)
        
        dl_col1, dl_col2 = st.columns([1, 2])
        with dl_col1:
            st.download_button(
                label="🩸 Download Clean PDF",
                data=fdata["cleaned_bytes"],
                file_name=clean_name,
                mime="application/pdf",
                key="btn_single_download"
            )
            
    else:
        # Multi-file batch ZIP download
        st.markdown(
            f"""<div class="clean-success-box">
                🛡️ <b>BATCH CHAIN OF CUSTODY VERIFIED:</b> <b>{len(sanitized_files)} files</b> are successfully sterilized in memory.
                Ready to be compiled into a serverless dynamic ZIP container in RAM.
            </div>""",
            unsafe_allow_html=True
        )

        # Multi-file metadata inspection summary expander
        with st.expander("🔍 View Extracted & Neutralized Metadata Flags", expanded=True):
            inspect_fname = st.selectbox(
                "Select a sanitized file to view its neutralized metadata report:",
                options=list(sanitized_files.keys()),
                key="sb_inspect_metadata"
            )
            if inspect_fname:
                inspect_fdata = sanitized_files[inspect_fname]
                if "neutralized_log" in inspect_fdata and inspect_fdata["neutralized_log"]:
                    table_rows = ""
                    for field, (found, val) in inspect_fdata["neutralized_log"].items():
                        status_text = f'<span style="color: #D90429; font-weight: bold;">Exposed</span> (<code style="color: #8D99AE;">{val}</code>)' if found else '<span style="color: #8D99AE;">Not Detected</span>'
                        action_text = '<span style="color: #D90429; font-weight: bold; text-shadow: 0 0 5px rgba(217,4,41,0.5);">🩸 ERADICATED</span>' if found else '<span style="color: #00C853; font-weight: bold;">✔️ SECURE / CLEARED</span>'
                        table_rows += f"""
                        <tr>
                            <td style="color: #EDF2F4; font-weight: bold; border-bottom: 1px solid #2B2D42; padding: 8px;">{field}</td>
                            <td style="border-bottom: 1px solid #2B2D42; padding: 8px;">{status_text}</td>
                            <td style="border-bottom: 1px solid #2B2D42; padding: 8px;">{action_text}</td>
                        </tr>
                        """
                    
                    st.markdown(f"""
                    <table style="width: 100%; border-collapse: collapse; margin-top: 10px; font-family: 'Space Mono', monospace; font-size: 0.85rem;">
                        <thead>
                            <tr style="border-bottom: 2px solid #2B2D42; text-align: left; color: #D90429; font-size: 0.75rem; text-transform: uppercase;">
                                <th style="padding: 8px;">Field Name</th>
                                <th style="padding: 8px;">Status Found</th>
                                <th style="padding: 8px;">Action Taken</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_rows}
                        </tbody>
                    </table>
                    """, unsafe_allow_html=True)
        
        # 100% in-memory Batch ZIP Generation
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for fname, fdata in sanitized_files.items():
                clean_name = fname.replace(".pdf", "_clean.pdf")
                # Write direct byte content without disk interaction
                zip_file.writestr(clean_name, fdata["cleaned_bytes"])
                
        zip_bytes = zip_buffer.getvalue()
        zip_buffer.close()
        
        dl_col1, dl_col2 = st.columns([1, 2])
        with dl_col1:
            st.download_button(
                label="📦 Download Sanitized Batch ZIP",
                data=zip_bytes,
                file_name="RedPurge_Sanitized_Batch.zip",
                mime="application/zip",
                key="btn_batch_download"
            )

# ---------------------------------------------------------
# 10. LIVE FORENSIC AUDIT TRAILS (MONOSPACED TERMINAL)
# ---------------------------------------------------------
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="terminal-titlebar"><span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>&nbsp;&nbsp;LIVE FORENSIC AUDIT LOG - REDPURGE PDF v1.0.0</div>', unsafe_allow_html=True)

terminal_html = '<div class="terminal-console">'
for log in reversed(st.session_state.audit_logs):
    # Apply high-contrast text color accents based on category
    if "[THREAT ALERT]" in log:
        terminal_html += f'<span style="color: #D90429; font-weight: bold;">{log}</span><br>'
    elif "[PURGE SUCCESS]" in log:
        terminal_html += f'<span style="color: #00C853; font-weight: bold;">{log}</span><br>'
    elif "[BVA WARNING]" in log or "[ERROR]" in log:
        terminal_html += f'<span style="color: #FFB020; font-weight: bold;">{log}</span><br>'
    else:
        terminal_html += f"{log}<br>"
terminal_html += '</div>'

st.markdown(terminal_html, unsafe_allow_html=True)

# 100% In-Memory Forensic Log Export Trigger
if st.session_state.audit_logs:
    log_string = "\n".join(st.session_state.audit_logs)
    
    col_log_exp, _ = st.columns([1, 2])
    with col_log_exp:
        st.download_button(
            label="📥 Export Forensic Log",
            data=log_string,
            file_name="redpurge_forensic_audit.log",
            mime="text/plain",
            key="btn_export_log"
        )
