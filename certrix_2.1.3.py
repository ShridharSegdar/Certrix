#!/usr/bin/env python3
"""
Certrix 2.2 – Persistent CA + New / Renew / Bulk Renew + CSR Preview (Modal UI)

Features:
 - Persistent CA saved to ~/.certrix/ca_store/
 - CA CN: "ICICI Bank Certifying Authority for H2H"
 - New cert:
      * generates key + CSR + cert (signed by CA) + legacy PFX (3DES+SHA1)
      * returns ZIP: <CN>.prv, <CN>.csr, <CN>.cer, <CN>.pfx, ca_certificate.cer
 - Renew:
      * accepts CSR (file or pasted)
      * auto-detects PEM / DER
      * signs with CA
      * returns <CN>.cer (filename derived from CN / prefix)
 - CSR preview:
      * endpoint /csr_preview
      * returns JSON with subject fields (CN, O, OU, C, ST, L)
      * UI shows popup modal
 - Bulk renew:
      * accepts ZIP containing multiple .csr/.pem/.der
      * signs each CSR with CA
      * returns renewed_<N>_certs.zip containing <CN>.cer
"""

from flask import (
    Flask,
    request,
    render_template_string,
    send_file,
    abort,
    jsonify,
)
from cryptography import x509
from cryptography.x509.oid import (
    NameOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)
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
# For Linux/PythonAnywhere you can instead do:
# OPENSSL_BIN = os.environ.get("OPENSSL_BIN") or _shutil.which("openssl")

CA_DIR = Path.home() / ".certrix" / "ca_store"
CA_KEY_FILE = CA_DIR / "ca_key.pem"
CA_CERT_FILE = CA_DIR / "ca_cert.pem"

CA_COMMON_NAME = "ICICI Bank Certifying Authority for H2H"
CA_ORG = "ICICI Bank"
CA_COUNTRY = "IN"


# ---------- Template (UI: new+renew+bulk+modal) ----------
TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Certrix 2.2 — Digital Certificate Generator</title>
<style>
:root{
  --bg:#071018;
  --muted:#9fb0c0;
  --accent-1:#5f7cf2;
  --glass-border: rgba(255,255,255,0.04);
}
html,body{
  height:100%;
  margin:0;
  font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial;
  background:var(--bg);
  color:#eaf5ff;
  -webkit-font-smoothing:antialiased;
}
body::before{
  content:"";
  position:fixed;
  inset:0;
  z-index:0;
  background: linear-gradient(180deg, rgba(6,9,14,0.62), rgba(4,6,10,0.72));
  pointer-events:none;
}
.bg-pattern{
  position:fixed;
  inset:0;
  z-index:0;
  background-size:cover;
  background-position:center;
  opacity:0.12;
  mix-blend-mode:overlay;
  pointer-events:none;
  filter: contrast(0.9) saturate(0.8);
}
.wrap{
  position:relative;
  z-index:2;
  max-width:1100px;
  margin:36px auto;
  padding:18px;
  box-sizing:border-box;
}
.panel{
  background: linear-gradient(180deg, rgba(20,28,34,0.72), rgba(8,12,16,0.78));
  border-radius:18px;
  border:1px solid rgba(255,255,255,0.03);
  padding:22px;
  box-shadow: 0 12px 36px rgba(0,0,0,0.6);
  backdrop-filter: blur(6px) saturate(1.05);
}
.title-row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  margin-bottom:12px;
}
.logo{
  font-weight:800;
  letter-spacing:0.8px;
  font-size:13px;
  color:#cfe6ff;
}
h1{
  margin:0 0 6px;
  font-size:24px;
  color:#eaf5ff;
}
p.lead{
  margin:0;
  color:var(--muted);
  font-size:13px;
}

/* grid */
.panel-grid{
  display:grid;
  grid-template-columns: 1fr 380px;
  gap:24px;
  align-items:flex-start;
  margin-bottom:20px;
}
@media (max-width:980px){
  .panel-grid{ grid-template-columns:1fr; }
}

/* sections */
.section{
  background: rgba(255,255,255,0.012);
  border-radius:12px;
  border: 1px solid rgba(255,255,255,0.035);
  padding:16px;
  position:relative;
  z-index:1;
  overflow:visible;
  margin-top:18px;
}
.section:first-of-type{
  margin-top:0;
}
.section.output-box{
  background: linear-gradient(180deg, rgba(255,255,255,0.015), rgba(255,255,255,0.008));
}

/* labels & inputs */
label.small{
  display:block;
  font-size:11px;
  color:var(--muted);
  margin-bottom:8px;
  font-weight:700;
  letter-spacing:0.6px;
}
.input{
  box-sizing:border-box;
  padding-left:14px;
  padding-right:52px;
  min-height:44px;
  line-height:1.2;
  display:block;
  position:relative;
  z-index:2;
  width:100%;
  border-radius:10px;
  border:1px solid rgba(255,255,255,0.03);
  background:rgba(255,255,255,0.02);
  color:#dff0ff;
  font-size:14px;
  outline:none;
  transition: box-shadow .12s, border-color .12s;
}
textarea.input{
  min-height:100px;
  padding-top:10px;
  padding-bottom:10px;
  resize:vertical;
}
input::placeholder, textarea::placeholder{
  color: rgba(220,235,250,0.17);
}
input:focus, textarea:focus, select:focus{
  box-shadow: 0 10px 28px rgba(80,100,255,0.06);
  border-color: rgba(115,140,255,0.12);
}
select.input{ padding-right:36px; }

/* layout rows */
.row{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:18px;
  align-items:stretch;
  margin-top:12px;
}
.single{ margin-top:12px; }

/* buttons & messages */
.footer-row{
  display:flex;
  gap:12px;
  align-items:center;
  margin-top:16px;
  flex-wrap:wrap;
}
.btn{
  background: linear-gradient(180deg,var(--accent-1), #6b8cff);
  color:white;
  border:0;
  padding:10px 14px;
  border-radius:10px;
  cursor:pointer;
  font-weight:700;
  box-shadow:0 10px 28px rgba(20,30,60,0.45);
}
.btn.ghost{
  background:transparent;
  border:1px solid rgba(255,255,255,0.04);
  color:var(--muted);
  padding:8px 12px;
  border-radius:10px;
}
.btn.small{
  font-size:12px;
  padding:6px 10px;
}
.muted{
  color:var(--muted);
  font-size:13px;
}
.hint{
  font-size:12px;
  color:var(--muted);
  margin-top:6px;
}
.msg{
  padding:10px 12px;
  border-radius:8px;
  margin-top:8px;
  font-weight:700;
  font-size:13px;
}
.ok{ background: rgba(16,185,129,0.08); color:#7ee3c1; }
.err{ background: rgba(239,68,68,0.06); color:#ffb4b4; }

footer.site{
  text-align:center;
  margin-top:18px;
  color:var(--muted);
  font-size:12px;
}

/* autofill */
input:-webkit-autofill,
input:-webkit-autofill:hover,
input:-webkit-autofill:focus{
  -webkit-box-shadow: 0 0 0px 1000px rgba(255,255,255,0.02) inset !important;
  box-shadow: 0 0 0px 1000px rgba(255,255,255,0.02) inset !important;
}

/* modal */
.modal-backdrop{
  position:fixed;
  inset:0;
  background:rgba(0,0,0,0.65);
  display:flex;
  align-items:center;
  justify-content:center;
  z-index:50;
}
.modal{
  width:100%;
  max-width:480px;
  background:linear-gradient(180deg, rgba(15,20,28,0.98), rgba(6,10,16,0.98));
  border-radius:16px;
  border:1px solid rgba(255,255,255,0.08);
  box-shadow:0 18px 40px rgba(0,0,0,0.85);
  padding:16px 18px 14px;
}
.modal-header{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:8px;
  margin-bottom:10px;
}
.modal-header h3{
  margin:0;
  font-size:16px;
}
.modal-close{
  background:transparent;
  border:0;
  color:#9fb0c0;
  font-size:20px;
  cursor:pointer;
}
.modal-body{
  font-size:13px;
  color:#dce9f7;
}
.modal-body table{
  width:100%;
  border-collapse:collapse;
  font-size:13px;
}
.modal-body th,
.modal-body td{
  padding:4px 0;
  text-align:left;
}
.modal-body th{
  width:110px;
  color:#9fb0c0;
  font-weight:600;
}
.modal-footer{
  text-align:right;
  margin-top:10px;
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
        <div class="logo"></div>
        <h1>Certrix - Digital Certificate Generator</h1>
        <p class="lead">
          Create new certificates or renew existing ones from CSR, signed by the persisted CA.<br>
          
        </p>
      </div>
      <div style="color:var(--muted); font-size:12px">Certrix 2.2.3</div>
    </div>

    <!-- New certificate -->
    <div class="panel-grid">
      <form id="newForm" method="post" action="/generate" style="min-width:0">
        <div class="section">
          <label class="small">Common Name (CN)</label>
          <input class="input" name="cn" required maxlength="128" placeholder="Common Name " />

          <div class="row">
            <div>
              <label class="small">Country (2-letter)</label>
              <input class="input" name="country" maxlength="2" placeholder="Country Eg:IN" />
            </div>
            <div>
              <label class="small">State / Province</label>
              <input class="input" name="state" placeholder="State" />
            </div>
          </div>

          <div class="single">
            <label class="small">Locality / City</label>
            <input class="input" name="locality" placeholder="Locality" />
          </div>

          <div class="row">
            <div>
              <label class="small">Organization (O)</label>
              <input class="input" name="org" placeholder="Organization" />
            </div>
            <div>
              <label class="small">Organizational Unit (OU)</label>
              <input class="input" name="ou" placeholder="Organizational Unit" />
            </div>
          </div>

          <div class="row">
            <div>
              <label class="small">Validity (years)</label>
              <input class="input" name="years" type="number" value="5" min="5" max="50" />
            </div>
            <div>
              <label class="small">RSA key size (bits)</label>
              <select class="input" name="key_size">
                <option>2048</option>
                <option>3072</option>
                <option>4096</option>
              </select>
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
            <button id="newSubmit" class="btn" type="submit">
              <span id="newSpinner" style="display:none">⏳</span>&nbsp;
              Generate &amp; Download ZIP
            </button>
            <button type="button" class="btn ghost" onclick="resetNewForm()">Reset</button>
            <div id="newMsg" style="flex:1"></div>
          </div>
          <div class="hint">
            Tip: use ASCII-only passphrases for max compatibility. Avoid empty PFX password if possible.
          </div>
        </div>
      </form>

      <aside class="section output-box">
        <h3 style="margin:0 0 6px">Output (New certificate)</h3>
        <ul style="margin-left:18px; color:var(--muted); padding-left:0">
          <li><strong>certificate.prv</strong> — Private key (PEM)</li>
          <li><strong>certificate.csr</strong> — CSR (PEM)</li>
          <li><strong>certificate.cer</strong> — End-entity certificate (PEM)</li>
          <li><strong>certificate.pfx</strong> — PKCS#12 / PFX (legacy 3DES+SHA1, chain included)</li>
        </ul>
        <hr style="border:none; height:1px; background:rgba(255,255,255,0.03); margin:10px 0">
      
      </aside>
    </div>

    <!-- Renew single CSR -->
    <div class="section">
      <h3 style="margin-top:0;margin-bottom:6px;">Renew certificate from existing CSR</h3>
      <p class="muted" style="margin-top:0;margin-bottom:10px;">
        Upload a CSR file (<code>.csr</code>, <code>.pem</code>, <code>.der</code>) or paste CSR text.
        Certrix will auto-detect PEM/DER, sign with the persistent CA and return a renewed <code>&lt;CN&gt;.cer</code>.
      </p>

      <form id="renewForm" method="post" action="/renew" enctype="multipart/form-data">
        <div class="single">
          <label class="small">CSR file (optional)</label>
          <input class="input" type="file" name="csr_file" accept=".csr,.pem,.der,.txt" />
        </div>

        <div class="single">
          <label class="small">Or paste CSR (PEM text)</label>
          <textarea class="input" name="csr_text" placeholder="-----BEGIN CERTIFICATE REQUEST-----"></textarea>
        </div>

        <div class="single">
          <label class="small">Validity (years)</label>
          <input class="input" name="years" type="number" value="5" min="5" max="50" />
        </div>

        <div class="footer-row">
          <button type="button" class="btn small" onclick="previewCsr()">Preview CSR</button>
          <button id="renewSubmit" class="btn" type="submit">
            <span id="renewSpinner" style="display:none">⏳</span>&nbsp;
            Sign CSR &amp; Download CER
          </button>
          <div id="renewMsg" style="flex:1"></div>
        </div>
        <div class="hint">
          Subject and public key come from the CSR. CA and validity are controlled here.
        </div>
      </form>
    </div>

    <!-- Bulk CSR renewal -->
    <div class="section">
      <h3 style="margin-top:0;margin-bottom:6px;">Bulk CSR renewal (ZIP → ZIP)</h3>
      <p class="muted" style="margin-top:0;margin-bottom:10px;">
        Upload a ZIP containing multiple CSR files. For each valid CSR, Certrix will issue
        a renewed certificate named <code>&lt;CN&gt;.cer</code> and return a ZIP with all renewed certs.
      </p>

      <form id="bulkForm" method="post" action="/renew_bulk" enctype="multipart/form-data">
        <div class="row">
          <div>
            <label class="small">CSR ZIP file</label>
            <input class="input" type="file" name="csr_zip" accept=".zip" />
          </div>
          <div>
            <label class="small">Validity (years)</label>
            <input class="input" name="years" type="number" value="5" min="5" max="50" />
          </div>
        </div>
        <div class="footer-row">
          <button id="bulkSubmit" class="btn" type="submit">
            <span id="bulkSpinner" style="display:none">⏳</span>&nbsp;
            Renew All &amp; Download ZIP
          </button>
          <div id="bulkMsg" style="flex:1"></div>
        </div>
      </form>
    </div>

    <footer class="site">
       Certrix
    </footer>
  </div>
</div>

<!-- CSR Preview Modal -->
<div id="csrModal" class="modal-backdrop" style="display:none;">
  <div class="modal">
    <div class="modal-header">
      <h3>CSR Preview</h3>
      <button type="button" class="modal-close" onclick="closeModal()">×</button>
    </div>
    <div class="modal-body">
      <div id="csrModalBody">
        Loading…
      </div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn ghost" onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<script>
  const newForm   = document.getElementById('newForm');
  const newMsg    = document.getElementById('newMsg');
  const newBtn    = document.getElementById('newSubmit');
  const newSpin   = document.getElementById('newSpinner');

  const renewForm = document.getElementById('renewForm');
  const renewMsg  = document.getElementById('renewMsg');
  const renewBtn  = document.getElementById('renewSubmit');
  const renewSpin = document.getElementById('renewSpinner');

  const bulkForm  = document.getElementById('bulkForm');
  const bulkMsg   = document.getElementById('bulkMsg');
  const bulkBtn   = document.getElementById('bulkSubmit');
  const bulkSpin  = document.getElementById('bulkSpinner');

  const csrModal      = document.getElementById('csrModal');
  const csrModalBody  = document.getElementById('csrModalBody');

  function showMsg(el, text, type){
    el.innerHTML = '<div class="msg '+(type==='err'?'err':'ok')+'">'+text+'</div>';
  }
  function resetNewForm(){
    newForm.reset();
    newMsg.innerHTML = '';
  }
  function openModal(){
    csrModal.style.display = 'flex';
  }
  function closeModal(){
    csrModal.style.display = 'none';
  }

  // New certificate: JSON POST, download ZIP
  newForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    newMsg.innerHTML = '';
    newBtn.disabled = true;
    newSpin.style.display = 'inline-block';
    const fd = new FormData(newForm);
    const body = {};
    fd.forEach((v,k)=> body[k]=v);
    try{
      const resp = await fetch(newForm.action, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body)
      });
      if(!resp.ok){
        const t = await resp.text().catch(()=>resp.statusText);
        showMsg(newMsg, 'Error: '+t, 'err');
        return;
      }
      const blob = await resp.blob();
      const cd = resp.headers.get('Content-Disposition') || '';
      const match = cd.match(/filename="(.+)"/);
      const filename = match ? match[1] : 'certs.zip';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showMsg(newMsg, 'Download started: '+filename, 'ok');
    }catch(err){
      showMsg(newMsg, 'Server or network error', 'err');
    }finally{
      newBtn.disabled = false;
      newSpin.style.display = 'none';
    }
  });

  // Single renew: FormData POST, download CER
  renewForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    renewMsg.innerHTML = '';
    renewBtn.disabled = true;
    renewSpin.style.display = 'inline-block';
    const fd = new FormData(renewForm);
    try{
      const resp = await fetch(renewForm.action, {
        method:'POST',
        body: fd
      });
      if(!resp.ok){
        const t = await resp.text().catch(()=>resp.statusText);
        showMsg(renewMsg, 'Error: '+t, 'err');
        return;
      }
      const blob = await resp.blob();
      let filename = 'renewed.cer';
      const cd = resp.headers.get('Content-Disposition') || '';
      const m = cd.match(/filename="(.+)"/);
      if(m && m[1]) filename = m[1];
      const headerName = resp.headers.get('X-Suggested-Filename');
      if(headerName) filename = headerName;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showMsg(renewMsg, 'Renewed certificate download started: '+filename, 'ok');
    }catch(err){
      showMsg(renewMsg, 'Server or network error', 'err');
    }finally{
      renewBtn.disabled = false;
      renewSpin.style.display = 'none';
    }
  });

  // Bulk renew: ZIP → ZIP
  bulkForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    bulkMsg.innerHTML = '';
    bulkBtn.disabled = true;
    bulkSpin.style.display = 'inline-block';
    const fd = new FormData(bulkForm);
    const file = fd.get('csr_zip');
    if(!file || !file.name){
      showMsg(bulkMsg, 'Please select a ZIP file with CSR files.', 'err');
      bulkBtn.disabled = false;
      bulkSpin.style.display = 'none';
      return;
    }
    try{
      const resp = await fetch(bulkForm.action, {
        method:'POST',
        body: fd
      });
      if(!resp.ok){
        const t = await resp.text().catch(()=>resp.statusText);
        showMsg(bulkMsg, 'Error: '+t, 'err');
        return;
      }
      const blob = await resp.blob();
      const cd = resp.headers.get('Content-Disposition') || '';
      const m = cd.match(/filename="(.+)"/);
      const filename = m && m[1] ? m[1] : 'renewed_certs.zip';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      showMsg(bulkMsg, 'Bulk renewed ZIP download started: '+filename, 'ok');
    }catch(err){
      showMsg(bulkMsg, 'Server or network error', 'err');
    }finally{
      bulkBtn.disabled = false;
      bulkSpin.style.display = 'none';
    }
  });

  // CSR preview → modal
  async function previewCsr(){
    renewMsg.innerHTML = '';
    const fd = new FormData();
    const fileInput = renewForm.querySelector('input[name="csr_file"]');
    const textArea = renewForm.querySelector('textarea[name="csr_text"]');
    const f = fileInput.files[0];
    const txt = (textArea.value || '').trim();
    if(f){
      fd.append('csr_file', f);
    }
    if(txt){
      fd.append('csr_text', txt);
    }
    if(!f && !txt){
      showMsg(renewMsg, 'Please choose a CSR file or paste CSR text to preview.', 'err');
      return;
    }
    csrModalBody.innerHTML = 'Parsing CSR…';
    openModal();
    try{
      const resp = await fetch('/csr_preview', { method:'POST', body: fd });
      const data = await resp.json();
      if(!resp.ok || data.error){
        const msg = data && data.error ? data.error : 'Unknown error';
        csrModalBody.innerHTML = '<div style="color:#ffb4b4;">Preview error: '+msg+'</div>';
        return;
      }
      const subj = data.subject || {};
      const rows = [
        ['Common Name (CN)', subj.CN || ''],
        ['Organization (O)', subj.O || ''],
        ['Org Unit (OU)', subj.OU || ''],
        ['Country (C)', subj.C || ''],
        ['State / Province (ST)', subj.ST || ''],
        ['Locality / City (L)', subj.L || '']
      ];
      let html = '<table>';
      for(const [label,val] of rows){
        html += '<tr><th>'+label+'</th><td>'+ (val || '<span style="color:#637180;">(empty)</span>') +'</td></tr>';
      }
      html += '</table>';
      csrModalBody.innerHTML = html;
    }catch(err){
      csrModalBody.innerHTML = '<div style="color:#ffb4b4;">Server or network error during preview.</div>';
    }
  }
  window.previewCsr = previewCsr;
  window.closeModal = closeModal;
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

    # Create new CA
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
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
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


def _sanitize_field(s: str, max_len: int) -> str:
    if not s:
        return ""
    s = str(s)
    return "".join(
        ch for ch in s if ch.isalnum() or ch in " -_.@()&,/"
    )[:max_len].strip()


def _safe_cert_name(raw: str, default: str = "certificate") -> str:
    if not raw:
        return default
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


def load_csr_auto(data: bytes) -> x509.CertificateSigningRequest:
    """
    Smart CSR loader. Tries PEM first, then DER. Normalizes CRLF for Windows.
    """
    if b"-----BEGIN CERTIFICATE REQUEST-----" in data or b"-----BEGIN NEW CERTIFICATE REQUEST-----" in data:
        return x509.load_pem_x509_csr(data)
    data = data.replace(b"\r\n", b"\n")
    try:
        return x509.load_pem_x509_csr(data)
    except Exception:
        try:
            return x509.load_der_x509_csr(data)
        except Exception as e:
            raise ValueError(f"CSR is neither valid PEM nor DER: {e}")


def csr_subject_dict(csr: x509.CertificateSigningRequest):
    """
    Extract core subject fields from a CSR as a dict for preview.
    """
    subj = csr.subject

    def _get(oid):
        try:
            attrs = subj.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else ""
        except Exception:
            return ""

    return {
        "CN": _get(NameOID.COMMON_NAME),
        "C":  _get(NameOID.COUNTRY_NAME),
        "ST": _get(NameOID.STATE_OR_PROVINCE_NAME),
        "L":  _get(NameOID.LOCALITY_NAME),
        "O":  _get(NameOID.ORGANIZATION_NAME),
        "OU": _get(NameOID.ORGANIZATIONAL_UNIT_NAME),
    }


def sign_csr_with_ca_and_defaults(
    csr: x509.CertificateSigningRequest,
    ca_key,
    ca_cert,
    years: int,
) -> x509.Certificate:
    """
    Take a CSR and sign it with the persistent CA,
    applying default KeyUsage / EKU / SKI / AKI if not present.
    """
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

    # Copy extensions from CSR if any
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

    # Default SKI / AKI / KU / EKU if missing
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ca_ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    default_ku = x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
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

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


# ---------- Routes ----------

@app.route("/", methods=["GET"])
def index():
    bg_path = Path(app.static_folder) / "bg-pattern.jpg"
    return render_template_string(
        TEMPLATE,
        bg_exists=bg_path.exists(),
        ca_path=str(CA_KEY_FILE),
    )


@app.route("/generate", methods=["POST"])
def generate():
    """
    New certificate:
     - accepts JSON (fetch) or form post
     - returns ZIP with <CN>.prv/.csr/.cer/.pfx + CA cert
    """
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict(flat=True)

    cn = _sanitize_field(data.get("cn", ""), 128)
    if not cn:
        return abort(400, "CN required")

    country = _sanitize_field(data.get("country", ""), 2)
    state = _sanitize_field(data.get("state", ""), 64)
    locality = _sanitize_field(data.get("locality", ""), 64)
    org = _sanitize_field(data.get("org", ""), 128)
    ou = _sanitize_field(data.get("ou", ""), 128)

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
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(ee_key, hashes.SHA256())
    )

    now = datetime.datetime.utcnow()
    not_before = now - datetime.timedelta(minutes=1)
    not_after = add_years_exact(not_before, years)

    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=ca_ski.digest,
        authority_cert_issuer=None,
        authority_cert_serial_number=None,
    )
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    eku = x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    )

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
            openssl_bin,
            "pkcs12",
            "-export",
            "-out",
            str(pfx_path),
            "-inkey",
            str(ee_key_file),
            "-in",
            str(ee_cert_file),
            "-certfile",
            str(ca_cert_file),
            "-name",
            cn,
            "-certpbe",
            "PBE-SHA1-3DES",
            "-keypbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
            "-passout",
            f"pass:{pfx_pass}",
        ]
        if key_pass:
            cmd += ["-passin", f"pass:{key_pass}"]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
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
        return send_file(
            mem,
            as_attachment=True,
            download_name=zip_filename,
            mimetype="application/zip",
        )
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


@app.route("/renew", methods=["POST"])
def renew():
    """
    Renew certificate from CSR.
    - Accepts csr_file (uploaded) or csr_text (pasted)
    - Auto-detects PEM / DER
    - Signs with persistent CA
    - Returns <CN>.cer (CN trimmed at first "_")
    """
    csr_file = request.files.get("csr_file")
    csr_text = (request.form.get("csr_text") or "").strip()

    if csr_file and csr_file.filename:
        csr_bytes = csr_file.read()
        uploaded_name = Path(csr_file.filename).stem
    elif csr_text:
        csr_bytes = csr_text.encode("utf-8")
        uploaded_name = "certificate"
    else:
        return abort(400, "CSR file or CSR text is required")

    try:
        csr = load_csr_auto(csr_bytes)
    except Exception:
        return abort(400, "Could not parse CSR (PEM or DER).")

    def _safe_name(v: str, default: str = "certificate") -> str:
        if not v:
            return default
        s = "".join(ch for ch in v if ch.isalnum() or ch in "-_.@()").strip()
        return s or default

    try:
        cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_from_csr = cn_attr[0].value if cn_attr else ""
    except Exception:
        cn_from_csr = ""

    raw_name = cn_from_csr or uploaded_name
    client_id = raw_name.split("_", 1)[0]
    file_cn = _safe_name(client_id)

    try:
        years = int(request.form.get("years", "1") or 1)
        years = max(1, min(years, 50))
    except Exception:
        years = 1

    ca_key, ca_cert = get_or_create_ca()
    renewed_cert = sign_csr_with_ca_and_defaults(csr, ca_key, ca_cert, years)

    pem_bytes = renewed_cert.public_bytes(serialization.Encoding.PEM)
    mem = io.BytesIO(pem_bytes)
    mem.seek(0)

    response = send_file(
    mem,
    as_attachment=True,
    download_name=f"{file_cn}.cer",
    mimetype="application/x-pem-file",
  )

# Force correct filename format recognized by browsers
    response.headers["Content-Disposition"] = f'attachment; filename="{file_cn}.cer"'

    return response

@app.route("/csr_preview", methods=["POST"])
def csr_preview():
    """
    Preview CSR subject (CN, O, OU, etc.)
    Accepts:
      - csr_file (upload)
      - csr_text (pasted)
    Returns JSON {subject:{CN,O,OU,C,ST,L}, source:...}
    """
    if "csr_file" in request.files:
        f = request.files["csr_file"]
        if f.filename:
            try:
                csr_bytes = f.read()
                csr = load_csr_auto(csr_bytes)
                source = f.filename
                return jsonify({
                    "source": source,
                    "subject": csr_subject_dict(csr),
                })
            except Exception as e:
                return jsonify({"error": "Invalid CSR File", "detail": str(e)}), 400

    csr_text = (request.form.get("csr_text") or "").strip()
    if csr_text:
        try:
            if not csr_text.endswith("\n"):
                csr_text += "\n"
            csr = load_csr_auto(csr_text.encode("utf-8"))
            return jsonify({
                "source": "pasted",
                "subject": csr_subject_dict(csr),
            })
        except Exception as e:
            return jsonify({"error": "Invalid CSR Text", "detail": str(e)}), 400

    return jsonify({"error": "CSR file or CSR text is required"}), 400


@app.route("/renew_bulk", methods=["POST"])
def renew_bulk():
    """
    Bulk renewal:
      - Accepts csr_zip (ZIP of .csr/.pem/.der files)
      - Signs each CSR with persistent CA
      - Returns renewed_<N>_certs.zip containing <CN>.cer
    """
    zip_file = request.files.get("csr_zip")
    if not zip_file or not zip_file.filename:
        return abort(400, "csr_zip (ZIP file) is required")

    try:
        years = int(request.form.get("years", "1") or 1)
        years = max(1, min(years, 50))
    except Exception:
        years = 1

    ca_key, ca_cert = get_or_create_ca()

    try:
        in_mem = io.BytesIO(zip_file.read())
        with zipfile.ZipFile(in_mem, "r") as zin:
            out_mem = io.BytesIO()
            written_count = 0
            with zipfile.ZipFile(out_mem, "w", compression=zipfile.ZIP_DEFLATED) as zout:
                for info in zin.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename
                    lower = name.lower()
                    if not (
                        lower.endswith(".csr")
                        or lower.endswith(".pem")
                        or lower.endswith(".der")
                    ):
                        continue

                    csr_bytes = zin.read(info.filename)
                    try:
                        csr = load_csr_auto(csr_bytes)
                    except Exception:
                        continue

                    try:
                        cn_attr = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                        cn_from_csr = cn_attr[0].value if cn_attr else ""
                    except Exception:
                        cn_from_csr = ""

                    fallback = Path(name).stem
                    raw_name = cn_from_csr or fallback
                    client_id = raw_name.split("_", 1)[0]
                    file_cn = _safe_cert_name(client_id)

                    renewed_cert = sign_csr_with_ca_and_defaults(
                        csr, ca_key, ca_cert, years
                    )
                    pem_bytes = renewed_cert.public_bytes(serialization.Encoding.PEM)
                    zout.writestr(f"{file_cn}.cer", pem_bytes)
                    written_count += 1

            if written_count == 0:
                return abort(400, "No valid CSRs found in ZIP")

            out_mem.seek(0)
            out_name = f"renewed_{written_count}_certs.zip"
            return send_file(
                out_mem,
                as_attachment=True,
                download_name=out_name,
                mimetype="application/zip",
            )
    except zipfile.BadZipFile:
        return abort(400, "Input is not a valid ZIP file")


# ---- run ----
if __name__ == "__main__":
    print("Starting Certrix 2.2 on http://127.0.0.1:5000")
    if not OPENSSL_BIN and not _shutil.which("openssl"):
        print("Warning: OpenSSL not found on PATH. Set OPENSSL_BIN or install openssl.")
    print("CA store:", str(CA_DIR))
    app.run(host="127.0.0.1", port=5000, debug=False)
