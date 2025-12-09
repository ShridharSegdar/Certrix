#!/usr/bin/env python3
"""
certrix_persistent_ca_ui.py

Persistent CA + UI using your CSS template.
- Persistent CA saved to ~/.certrix/ca_store/
- CA CN: "ICICI Bank Certifying Authority for H2H"
- Exports legacy-compatible PFX using openssl pkcs12 -in <ee> -certfile <ca>
- Main form: create new key/CSR/cert/PFX ZIP
- Renew form: accept CSR (file upload or pasted), auto-detect PEM/DER, sign with CA and return renewed .cer
"""
from flask import Flask, request, render_template_string, send_file, abort
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import tempfile
import shutil
import subprocess
import io
import zipfile
import os
from pathlib import Path
import shutil as _shutil

app = Flask(__name__, static_folder="static")

# ---------- Config ----------
# For your Windows machine (works as you have it):
OPENSSL_BIN = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
# For PythonAnywhere / Linux, you would typically do:
# import shutil, os
# OPENSSL_BIN = os.environ.get("OPENSSL_BIN") or shutil.which("openssl")

CA_DIR = Path.home() / ".certrix" / "ca_store"
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"

CA_COMMON_NAME = "ICICI Bank Certifying Authority for H2H"
CA_ORG = "ICICI Bank"
CA_COUNTRY = "IN"

# ---------- Template (UI) ----------
TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Certrix — ICICI CA (persistent)</title>
<style>
:root{
  --bg:#071018;
  --muted:#9fb0c0;
  --accent-1:#5f7cf2;
  --glass-border: rgba(255,255,255,0.04);
}
html,body{height:100%; margin:0; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; background:var(--bg); color:#eaf5ff; -webkit-font-smoothing:antialiased;}
body::before{ content:""; position:fixed; inset:0; z-index:0; background: linear-gradient(180deg, rgba(6,9,14,0.62), rgba(4,6,10,0.72)); pointer-events:none; }

/* optional background pattern */
.bg-pattern{ position:fixed; inset:0; z-index:0; background-size:cover; background-position:center; opacity:0.12; mix-blend-mode:overlay; pointer-events:none; filter: contrast(0.9) saturate(0.8); }

.wrap{ position:relative; z-index:2; max-width:1100px; margin:36px auto; padding:18px; box-sizing:border-box; }
.panel{ background: linear-gradient(180deg, rgba(20,28,34,0.72), rgba(8,12,16,0.78)); border-radius:18px; border:1px solid rgba(255,255,255,0.03); padding:22px; box-shadow: 0 12px 36px rgba(0,0,0,0.6); backdrop-filter: blur(6px) saturate(1.05); }

.title-row{ display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:12px; }
.logo{ font-weight:800; letter-spacing:0.8px; font-size:13px; color:#cfe6ff }
h1{ margin:0 0 6px; font-size:24px; color:#eaf5ff }
p.lead{ margin:0; color:var(--muted); font-size:13px }

/* grid */
.panel-grid{ display:grid; grid-template-columns: 1fr 380px; gap:24px; align-items:start; }
@media (max-width:980px){ .panel-grid{ grid-template-columns:1fr } }

/* left form box */
.section.form-box{ background: rgba(255,255,255,0.012); border-radius:12px; border: 1px solid rgba(255,255,255,0.035); padding:16px; position:relative; z-index:1; overflow:visible; }

/* right output box */
.section.output-box{ background: linear-gradient(180deg, rgba(255,255,255,0.015), rgba(255,255,255,0.008)); border-radius:12px; padding:16px; border:1px solid rgba(255,255,255,0.03); position:relative; z-index:1; }

label.small{ display:block; font-size:11px; color:var(--muted); margin-bottom:8px; font-weight:700; letter-spacing:0.6px; }

/* INPUT fixes to avoid overlapping browser icons */
.input {
  box-sizing: border-box;
  padding-left: 14px;
  padding-right: 52px;  /* reserve room for password-manager icons */
  min-height: 44px;
  line-height: 1.2;
  display: block;
  position: relative;
  z-index: 2;
  width:100%;
  border-radius:10px;
  border:1px solid rgba(255,255,255,0.03);
  background: rgba(255,255,255,0.02);
  color:#dff0ff;
  font-size:14px;
  outline:none;
  transition: box-shadow .12s, border-color .12s;
}
input::placeholder { color: rgba(220,235,250,0.09); }
input:focus { box-shadow: 0 10px 28px rgba(80,100,255,0.06); border-color: rgba(115,140,255,0.12); }

select.input { padding-right:36px; }

/* rows & spacing */
.row { display: grid; grid-template-columns: 1fr 1fr; gap:18px; align-items: stretch; margin-top:12px; }
.single { margin-top:12px; }

/* buttons */
.footer-row { display:flex; gap:12px; align-items:center; margin-top:16px; flex-wrap:wrap; }
.btn { background: linear-gradient(180deg,var(--accent-1), #6b8cff); color:white; border:0; padding:10px 14px; border-radius:10px; cursor:pointer; font-weight:700; box-shadow:0 10px 28px rgba(20,30,60,0.45); }
.btn.ghost { background:transparent; border:1px solid rgba(255,255,255,0.04); color:var(--muted); padding:8px 12px; border-radius:10px; }

.muted { color:var(--muted); font-size:13px; }
.hint { font-size:12px; color:var(--muted); margin-top:6px; }

.msg { padding:10px 12px; border-radius:8px; margin-top:8px; font-weight:700; font-size:13px; }
.ok { background: rgba(16,185,129,0.08); color:#7ee3c1; }
.err { background: rgba(239,68,68,0.06); color:#ffb4b4; }

footer.site { text-align:center; margin-top:18px; color:var(--muted); font-size:12px; }

input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus {
  -webkit-box-shadow: 0 0 0px 1000px rgba(255,255,255,0.02) inset !important;
  box-shadow: 0 0 0px 1000px rgba(255,255,255,0.02) inset !important;
}

/* CSR textarea */
textarea.input {
  min-height: 140px;
  padding-top: 10px;
  padding-bottom: 10px;
  resize: vertical;
}
</style>
</head>
<body>
  {% if bg_exists %}
  <div class="bg-pattern" style="background-image:url('/static/bg-pattern.jpg')"></div>
  {% endif %}

  <div class="wrap">
    <div class="panel">
      <div class="title-row">
        <div>
          <div class="logo">Local Certificate Generator (Persistent CA)</div>
          <h1>Digital Certificate Generator</h1>
          <p class="lead">Create new certificates or renew existing ones from CSR, signed by the persisted CA.</p>
        </div>
        <div style="color:var(--muted); font-size:12px">Certrix</div>
      </div>

      <!-- MAIN GRID: New cert -->
      <div class="panel-grid">
        <!-- LEFT: form for NEW key/CSR/cert/PFX -->
        <form id="form" method="post" action="/generate" style="min-width:0">
          <div class="section form-box">
            <label class="small">Common Name (CN)</label>
            <input class="input" name="cn" required maxlength="128" placeholder="SHRI" />

            <div class="row">
              <div>
                <label class="small">Country (2-letter)</label>
                <input class="input" name="country" maxlength="2" placeholder="IN" />
              </div>
              <div>
                <label class="small">State / Province</label>
                <input class="input" name="state" placeholder="Maharashtra" />
              </div>
            </div>

            <div class="single">
              <label class="small">Locality / City</label>
              <input class="input" name="locality" placeholder="Mumbai" />
            </div>

            <div class="row">
              <div>
                <label class="small">Organization (O)</label>
                <input class="input" name="org" placeholder="ICICI Bank H2H" />
              </div>
              <div>
                <label class="small">Organizational Unit (OU)</label>
                <input class="input" name="ou" placeholder="IT" />
              </div>
            </div>

            <div class="row">
              <div>
                <label class="small">Validity (years)</label>
                <input class="input" name="years" type="number" value="1" min="1" max="50" />
              </div>
              <div>
                <label class="small">RSA key size (bits)</label>
                <select class="input" name="key_size"><option>2048</option><option>3072</option><option>4096</option></select>
              </div>
            </div>

            <div class="row">
              <div>
                <label class="small">Private key passphrase</label>
                <input class="input" name="key_pass" type="password" autocomplete="new-password" />
              </div>
              <div>
                <label class="small">PFX passphrase</label>
                <input class="input" name="pfx_pass" type="password" autocomplete="new-password" />
              </div>
            </div>

            <div class="footer-row">
              <button id="submitBtn" class="btn" type="submit"><span id="spinner" style="display:none">⏳</span>&nbsp;Generate &amp; Download ZIP</button>
              <button type="button" class="btn ghost" onclick="resetForm()">Reset</button>
              <div id="msg" style="flex:1"></div>
            </div>

            <div class="hint">Tip: use ASCII-only passphrases for max compatibility. Avoid empty PFX password if possible.</div>
          </div>
        </form>

        <!-- RIGHT: output description -->
        <aside class="section output-box">
          <h3 style="margin:0 0 6px">Output (New certificate)</h3>
          <ul style="margin-left:18px; color:var(--muted)">
            <li><strong>&lt;CN&gt;.prv</strong> — Private key (PEM)</li>
            <li><strong>&lt;CN&gt;.csr</strong> — CSR (PEM)</li>
            <li><strong>&lt;CN&gt;.cer</strong> — End-entity certificate (PEM)</li>
            <li><strong>&lt;CN&gt;.pfx</strong> — PKCS#12 / PFX (legacy 3DES+SHA1) (chain included)</li>
          </ul>
          <hr style="border:none; height:1px; background:rgba(255,255,255,0.03); margin:10px 8px">
          <p class="muted">CA key is persisted at <code>{{ ca_path }}</code>. Protect that file (chmod 600) and limit access in production.</p>
        </aside>
      </div>

      <!-- SECOND SECTION: CSR renewal -->
      <div style="margin-top:26px;">
        <div class="section form-box">
          <h3 style="margin-top:0; margin-bottom:8px;">Renew certificate from existing CSR</h3>
          <p class="muted" style="margin-top:0;margin-bottom:10px;">
            Upload a CSR file (<code>.csr</code>, <code>.pem</code>, <code>.der</code>) or paste the CSR text.
            The app will auto-detect PEM/DER, sign it with the CA and return a renewed <code>.cer</code>.
          </p>
          <form id="renewForm" method="post" action="/renew" enctype="multipart/form-data">
            <label class="small">CSR file (optional)</label>
            <input class="input" type="file" name="csr_file" id="csr_file" accept=".csr,.pem,.der,.txt" />

            <div class="hint">Or paste the CSR below if you prefer.</div>

            <label class="small" style="margin-top:12px;">CSR (PEM text)</label>
            <textarea class="input" name="csr_text" placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"></textarea>

            <div class="row">
              <div>
                <label class="small">Validity (years)</label>
                <input class="input" name="years" type="number" value="1" min="1" max="50" />
              </div>
              <div>
                <label class="small">Notes</label>
                <input class="input" name="note" placeholder="Internal note (not in cert)" />
              </div>
            </div>

            <div class="footer-row">
              <button id="renewSubmitBtn" class="btn" type="submit">
                <span id="renewSpinner" style="display:none">⏳</span>&nbsp;Sign CSR &amp; Download CER
              </button>
              <div id="renewMsg" style="flex:1"></div>
            </div>
            <div class="hint">Subject and public key come from the CSR. CA and validity are controlled here.</div>
          </form>
        </div>
      </div>

      <footer class="site">Certrix • Persistent CA &amp; CSR renewal</footer>
    </div>
  </div>

<script>
  // NEW CERT form (JSON POST as before)
  const form = document.getElementById('form'),
        submitBtn = document.getElementById('submitBtn'),
        spinner = document.getElementById('spinner'),
        msg = document.getElementById('msg');

  function showMsg(t,type='ok'){ msg.innerHTML = '<div class="msg '+(type==='ok'?'ok':'err')+'">'+t+'</div>'; }
  function resetForm(){ form.reset(); msg.innerHTML=''; }

  form.addEventListener('submit', async (e)=>{
    e.preventDefault();
    msg.innerHTML=''; submitBtn.disabled=true; spinner.style.display='inline-block';
    const fd = new FormData(form); const body={}; fd.forEach((v,k)=> body[k]=v);
    try{
      const resp = await fetch(form.action, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body)
      });
      if(!resp.ok){
        const t = await resp.text().catch(()=>resp.statusText);
        showMsg('Error: '+t,'err'); return;
      }
      const blob = await resp.blob();
      const cd = resp.headers.get('Content-Disposition') || '';
      const filename = (cd.match(/filename="(.+)"/)||[])[1] || 'certs.zip';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showMsg('Download started: '+filename,'ok');
    }catch(err){
      showMsg('Server or network error','err');
    }finally{
      submitBtn.disabled=false; spinner.style.display='none';
    }
  });

  // CSR RENEW form (multipart/form-data with file upload)
  const renewForm = document.getElementById('renewForm'),
        renewBtn = document.getElementById('renewSubmitBtn'),
        renewSpinner = document.getElementById('renewSpinner'),
        renewMsg = document.getElementById('renewMsg');

  function showRenewMsg(t,type='ok'){ renewMsg.innerHTML = '<div class="msg '+(type==='ok'?'ok':'err')+'">'+t+'</div>'; }

  renewForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    showRenewMsg('', 'ok'); renewBtn.disabled=true; renewSpinner.style.display='inline-block';
    const fd = new FormData(renewForm); // DO NOT set Content-Type; browser handles multipart
    try{
      const resp = await fetch(renewForm.action, { method:'POST', body: fd });
      if(!resp.ok){
        const t = await resp.text().catch(()=>resp.statusText);
        showRenewMsg('Error: '+t,'err'); return;
      }

      const blob = await resp.blob();
const cd = resp.headers.get('Content-Disposition') || '';
const match = cd.match(/filename="(.+)"/);
const filename = match ? match[1] : null;  // no fallback here!

if (!filename) {
  showRenewMsg('Error: Server did not provide a filename','err');
  return;
     }
     
     const url = URL.createObjectURL(blob);
     const a = document.createElement('a');
     a.href = url; 
     a.download = filename;
     document.body.appendChild(a); 
     a.click(); 
     a.remove();
     URL.revokeObjectURL(url);
     showRenewMsg('Renewed certificate download started: '+ filename,'ok');
    }catch(err){
      showRenewMsg('Server or network error','err');
    }finally{
      renewBtn.disabled=false; renewSpinner.style.display='none';
    }
  });
</script>
</body>
</html>
"""

# ---------- Helpers: CA persistence ----------
def _ensure_ca_store():
    CA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CA_DIR, 0o700)
    except Exception:
        pass

def get_or_create_ca():
    _ensure_ca_store()
    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists():
        key_bytes = CA_KEY_FILE.read_bytes()
        cert_bytes = CA_CERT_FILE.read_bytes()
        ca_key = serialization.load_pem_private_key(key_bytes, password=None)
        ca_cert = x509.load_pem_x509_certificate(cert_bytes)
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG),
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
    ])
    now = datetime.datetime.utcnow()
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now.replace(year=now.year + 20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
    )
    ca_cert = ca_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    CA_KEY_FILE.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_FILE.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(CA_KEY_FILE, 0o600)
        os.chmod(CA_CERT_FILE, 0o644)
    except Exception:
        pass
    return ca_key, ca_cert

def _sanitize_field(s: str, max_len: int):
    if not s:
        return ""
    s = str(s)
    return "".join(ch for ch in s if ch.isalnum() or ch in " -_.@()&,/")[:max_len].strip()

def _safe_cert_name(raw: str, default: str = "certificate") -> str:
    if not raw:
        return default
    # only keep safe filename characters
    s = "".join(ch for ch in raw if ch.isalnum() or ch in "-_.@()").strip()
    return s or default

def add_years_exact(dt: datetime.datetime, years: int) -> datetime.datetime:
    try:
        return dt.replace(year=dt.year + years)
    except ValueError:
        # handle Feb 29 → Feb 28
        return dt.replace(year=dt.year + years, day=28)

def find_openssl():
    if OPENSSL_BIN:
        if Path(OPENSSL_BIN).is_file():
            return OPENSSL_BIN
        raise RuntimeError(f"OPENSSL_BIN set but not found: {OPENSSL_BIN}")
    cand = _shutil.which("openssl")
    if cand:
        return cand
    raise RuntimeError("OpenSSL not found on PATH. Install OpenSSL or set OPENSSL_BIN.")

# helper: auto-detect PEM vs DER CSR
def load_csr_auto(data: bytes) -> x509.CertificateSigningRequest:
    # if it clearly looks like PEM, try PEM first
    if b"-----BEGIN CERTIFICATE REQUEST-----" in data or b"-----BEGIN NEW CERTIFICATE REQUEST-----" in data:
        return x509.load_pem_x509_csr(data)
    # otherwise try PEM then DER
    try:
        return x509.load_pem_x509_csr(data)
    except Exception:
        return x509.load_der_x509_csr(data)

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    bg_path = Path(app.static_folder) / "bg-pattern.jpg"
    return render_template_string(TEMPLATE, bg_exists=bg_path.exists(), ca_path=str(CA_KEY_FILE))

@app.route("/generate", methods=["POST"])
def generate():
    data = request.get_json() or {}
    cn = _sanitize_field(data.get("cn",""), 128)
    if not cn:
        return abort(400, "CN required")
    country = _sanitize_field(data.get("country",""), 2)
    state = _sanitize_field(data.get("state",""), 64)
    locality = _sanitize_field(data.get("locality",""), 64)
    org = _sanitize_field(data.get("org",""), 128)
    ou = _sanitize_field(data.get("ou",""), 128)
    try:
        years = int(data.get("years", "1"))
        years = max(1, min(years, 50))
    except Exception:
        years = 1
    try:
        key_size = int(data.get("key_size", "2048"))
        if key_size not in (2048, 3072, 4096):
            key_size = 2048
    except Exception:
        key_size = 2048
    key_pass = data.get("key_pass") or None
    pfx_pass = data.get("pfx_pass") or ""

    # subject (for NEW cert)
    subject_attrs = [x for x in [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country) if country else None,
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state) if state else None,
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality) if locality else None,
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org) if org else None,
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou) if ou else None,
    ] if x is not None]
    subject = x509.Name(subject_attrs)

    ca_key, ca_cert = get_or_create_ca()

    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(ee_key, hashes.SHA256())

    now = datetime.datetime.utcnow()
    not_before = now - datetime.timedelta(minutes=1)
    not_after = add_years_exact(not_before, years)
    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ca_ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None
    )
    key_usage = x509.KeyUsage(
        digital_signature=True, content_commitment=True,
        key_encipherment=True, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False
    )
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])

    ee_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(key_usage, critical=True)
        .add_extension(eku, critical=False)
    )
    ee_cert = ee_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    tmpdir = Path(tempfile.mkdtemp(prefix="certrix-"))
    try:
        ee_key_file = tmpdir / f"{cn}.key.pem"
        ee_csr_file = tmpdir / f"{cn}.csr.pem"
        ee_cert_file = tmpdir / f"{cn}.cert.pem"
        ca_cert_file = tmpdir / "ca_cert.pem"

        if key_pass:
            enc = serialization.BestAvailableEncryption(key_pass.encode("utf-8"))
        else:
            enc = serialization.NoEncryption()
        ee_key_file.write_bytes(
            ee_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )
        ee_csr_file.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        ee_cert_file.write_bytes(ee_cert.public_bytes(serialization.Encoding.PEM))
        ca_cert_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        openssl_bin = find_openssl()
        pfx_path = tmpdir / f"{cn}.pfx"

        cmd = [
            openssl_bin, "pkcs12", "-export",
            "-out", str(pfx_path),
            "-inkey", str(ee_key_file),
            "-in", str(ee_cert_file),      # EE cert
            "-certfile", str(ca_cert_file),# CA cert
            "-name", cn,
            "-certpbe", "PBE-SHA1-3DES",
            "-keypbe", "PBE-SHA1-3DES",
            "-macalg", "sha1",
            "-passout", f"pass:{pfx_pass}"
        ]
        if key_pass:
            cmd += ["-passin", f"pass:{key_pass}"]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"OpenSSL pkcs12 failed: {proc.stderr}")

        zip_filename = f"{cn}_certs.zip"
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{cn}.prv", ee_key_file.read_bytes())
            z.writestr(f"{cn}.csr", ee_csr_file.read_bytes())
            z.writestr(f"{cn}.cer", ee_cert_file.read_bytes())
            z.writestr(f"{cn}.pfx", pfx_path.read_bytes())
            z.writestr("ca_certificate.cer", ca_cert_file.read_bytes())
        mem.seek(0)
        return send_file(mem, as_attachment=True, download_name=zip_filename, mimetype="application/zip")
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


@app.route("/renew", methods=["POST"])
def renew():
    """
    Renew certificate from CSR.
    - Accepts file field: csr_file  (or textarea: csr_text)
    - Auto-detects PEM / DER
    - Signs with persistent CA
    - Downloads <clientId>.cer   where clientId = CN up to first "_"
    """

    # ----- 1. Get CSR from file or text -----
    csr_file = request.files.get("csr_file")
    csr_text = (request.form.get("csr_text") or "").strip()

    if csr_file and csr_file.filename:
        csr_bytes = csr_file.read()
        uploaded_name = Path(csr_file.filename).stem  # e.g. BHUV571696054_ssl_signer
    elif csr_text:
        csr_bytes = csr_text.encode("utf-8")
        uploaded_name = "certificate"
    else:
        return abort(400, "CSR file or CSR text is required")

    # ----- 2. Auto-detect PEM / DER -----
    # If you already have load_csr_auto() helper, we reuse it.
    def _load_csr_auto(data: bytes):
        try:
            return x509.load_pem_x509_csr(data)
        except Exception:
            return x509.load_der_x509_csr(data)

    try:
        csr = _load_csr_auto(csr_bytes)
    except Exception:
        return abort(400, "Could not parse CSR (PEM or DER).")

    # ----- 3. Build safe filename based on CN / uploaded name -----
    def _safe_name(v: str, default: str = "certificate") -> str:
        if not v:
            return default
        s = "".join(ch for ch in v if ch.isalnum() or ch in "-_.@()").strip()
        return s or default

    # CN from CSR
    try:
        cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_from_csr = cn_attr[0].value if cn_attr else ""
    except Exception:
        cn_from_csr = ""

    raw_name = cn_from_csr or uploaded_name   # prefer CN, else filename
    client_id = raw_name.split("_", 1)[0]     # BHUV571696054_ssl_signer → BHUV571696054
    file_cn = _safe_name(client_id)

    # ----- 4. Validity (years) -----
    try:
        years = int(request.form.get("years", "1") or 1)
        years = max(1, min(years, 50))
    except Exception:
        years = 1

    # ----- 5. Load persistent CA -----
    ca_key, ca_cert = get_or_create_ca()

    # ----- 6. Build renewed certificate -----
    now = datetime.datetime.utcnow()
    not_before = now - datetime.timedelta(minutes=1)
    not_after = add_years_exact(not_before, years)

    public_key = csr.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # copy CSR extensions if any
    has_ski = has_aki = has_ku = has_eku = False
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
        if ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            has_ski = True
        elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            has_aki = True
        elif ext.oid == ExtensionOID.KEY_USAGE:
            has_ku = True
        elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
            has_eku = True

    # SKI / AKI / KeyUsage / EKU defaults if missing
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ca_ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    default_ku = x509.KeyUsage(
        digital_signature=True, content_commitment=True,
        key_encipherment=True, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False
    )
    default_eku = x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    )

    if not has_ski:
        builder = builder.add_extension(ski, critical=False)
    if not has_aki:
        builder = builder.add_extension(aki, critical=False)
    if not has_ku:
        builder = builder.add_extension(default_ku, critical=True)
    if not has_eku:
        builder = builder.add_extension(default_eku, critical=False)

    renewed_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # ----- 7. Return <clientId>.cer -----
    pem_bytes = renewed_cert.public_bytes(serialization.Encoding.PEM)
    mem = io.BytesIO(pem_bytes)
    mem.seek(0)

    return send_file(
        mem,
        as_attachment=True,
        download_name=f"{file_cn}.cer",
        mimetype="application/x-pem-file",
    )

# ---- run ----
if __name__ == "__main__":
    print("Starting Certrix (persistent CA + CSR renew) on http://127.0.0.1:5000")
    if not OPENSSL_BIN and not _shutil.which("openssl"):
        print("Warning: OpenSSL not found on PATH. Set OPENSSL_BIN or install openssl.")
    print("CA store:", str(CA_DIR))
    app.run(host="127.0.0.1", port=5000, debug=False)
