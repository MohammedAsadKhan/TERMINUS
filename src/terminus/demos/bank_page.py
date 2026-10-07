"""Fictional bank page used only in local demonstrations."""

BANK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>First Heritage Community Bank | Personal &amp; Commercial Banking</title>
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
    .header-action { background: var(--navy-900); color: #fff; text-decoration: none; font-size: 13px; font-weight: 700; padding: 10px 16px; border-radius: 8px; }
    .header-action:hover { background: var(--navy-700); }

    /* Main Container */
    .hero { max-width: 1200px; margin: 32px auto; padding: 0 24px; display: grid; grid-template-columns: 1fr 380px; gap: 32px; align-items: start; }

    /* Promo Pitch */
    .pitch { background: linear-gradient(135deg, var(--navy-900), var(--navy-800)); color: #fff; padding: 40px; border-radius: 16px; box-shadow: 0 8px 24px rgba(13,30,56,0.15); position: relative; overflow: hidden; }
    .pitch::after { content: ""; position: absolute; right: -50px; bottom: -50px; width: 220px; height: 220px; background: radial-gradient(circle, rgba(201,152,52,0.15), transparent 70%); border-radius: 50%; pointer-events: none; }
    .pitch .eyebrow { color: var(--gold-400); font-weight: 700; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 12px; }
    .pitch h2 { font-size: 32px; font-weight: 800; line-height: 1.2; margin-bottom: 16px; }
    .pitch p { color: #cbd5e1; font-size: 15px; margin-bottom: 24px; line-height: 1.6; }
    .hero-link { display: inline-block; background: var(--gold-400); color: var(--navy-900); padding: 11px 18px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 700; margin-bottom: 26px; }
    .hero-link:hover { background: #f0c97a; }
    .features-list { list-style: none; display: flex; flex-direction: column; gap: 10px; font-size: 14px; color: #e2e8f0; }
    .features-list li::before { content: "✓ "; color: var(--gold-400); font-weight: bold; margin-right: 6px; }

    /* Login / Portal Box */
    .portal-box { background: #fff; border: 1px solid var(--gray-200); border-radius: 16px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.04); }
    .portal-box h3 { font-size: 20px; font-weight: 700; color: var(--navy-900); margin-bottom: 4px; }
    .portal-box p { font-size: 13px; color: var(--gray-600); margin-bottom: 20px; }
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

    /* Banking products and branch search */
    .bank-section { max-width: 1200px; margin: 0 auto 42px; padding: 0 24px; }
    .section-heading { margin-bottom: 18px; }
    .section-heading h2 { color: var(--navy-900); font-size: 26px; margin-bottom: 4px; }
    .section-heading p { color: var(--gray-600); font-size: 14px; }
    .product-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
    .product-card { background: #fff; border: 1px solid var(--gray-200); border-radius: 14px; padding: 25px; box-shadow: 0 4px 12px rgba(0,0,0,.025); }
    .product-card .icon { display: flex; align-items: center; justify-content: center; width: 42px; height: 42px; border-radius: 11px; background: var(--gold-100); color: var(--navy-900); font-size: 22px; margin-bottom: 14px; }
    .product-card h3 { color: var(--navy-900); font-size: 17px; margin-bottom: 8px; }
    .product-card p { color: var(--gray-600); font-size: 13px; margin-bottom: 12px; }
    .product-card a { color: var(--navy-700); font-size: 13px; font-weight: 700; text-decoration: none; }
    .branch-card { display: grid; grid-template-columns: 1fr 1fr; gap: 28px; align-items: center; background: #fff; border: 1px solid var(--gray-200); border-radius: 14px; padding: 28px; }
    .branch-card h2 { color: var(--navy-900); font-size: 24px; margin-bottom: 8px; }
    .branch-card p { color: var(--gray-600); font-size: 14px; }
    .search-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .search-row input { flex: 1; padding: 10px 14px; border: 1px solid var(--gray-200); border-radius: 8px; font-size: 13px; min-width: 0; }
    .btn-action { padding: 10px 16px; width: auto; font-size: 13px; border-radius: 8px; }
    .feedback { color: var(--gray-600); font-size: 12px; margin-top: 12px; min-height: 18px; }
    .feedback.error { color: #a52b2b; }
    .branch-result { background: var(--gray-50); border: 1px solid var(--gray-200); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 13px; }

    /* Footer */
    footer { background: #fff; border-top: 1px solid var(--gray-200); padding: 32px 24px; text-align: center; font-size: 12px; color: var(--gray-600); }
    .footer-links { display: flex; justify-content: center; gap: 20px; margin-bottom: 16px; }
    .footer-links a { color: var(--navy-800); text-decoration: none; }
    @media (max-width: 900px) { .hero, .branch-card { grid-template-columns: 1fr; } .product-grid { grid-template-columns: 1fr; } nav { display: none; } }
  </style>
</head>
<body>

  <div class="top-bar">
    <div>
      <span>Welcome to First Heritage Community Bank</span>
    </div>
    <div>
      <a href="#locations">Find a branch</a>
      <a href="#support">Contact us</a>
    </div>
  </div>

  <header>
    <a href="/bank/" class="logo">
      <div class="logo-badge">FH</div>
      <div class="logo-text">
        <h1>FIRST HERITAGE</h1>
        <p>COMMUNITY BANK</p>
      </div>
    </a>
    <nav>
      <a href="#personal" class="active">Personal</a>
      <a href="#business">Business</a>
      <a href="#lending">Lending</a>
      <a href="#locations">Locations</a>
    </nav>
    <a href="#online-banking" class="header-action">Online Banking</a>
  </header>

  <div class="hero">

    <!-- Left Pitch Card -->
    <div class="pitch">
      <div class="eyebrow">Banking that feels like home</div>
      <h2>Your money has places to go. We help you get there.</h2>
      <p>Everyday accounts, lending, and a team that takes the time to know your goals. Bank online or visit us in your neighborhood.</p>
      <a href="#personal" class="hero-link">Explore personal banking &rarr;</a>

      <ul class="features-list">
        <li>Manage checking and savings in one place</li>
        <li>Transfer funds with online banking</li>
        <li>Get help from a local banking team</li>
      </ul>
    </div>

    <!-- Right Login / Customer Portal Card -->
    <div class="portal-box" id="online-banking">

      <!-- Login View -->
      <div id="login-view">
        <h3>Online Banking</h3>
        <p>Sign in to view accounts and move money.</p>

        <form onsubmit="handleLogin(event)">
          <div class="form-group">
            <label>Username / Online ID</label>
            <input type="text" id="username" autocomplete="username" placeholder="Enter your Online ID" required />
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" id="password" autocomplete="current-password" placeholder="Enter your password" required />
          </div>
          <button type="submit" class="btn btn-primary" id="login-btn">Sign In to Accounts</button>
        </form>
        <p class="feedback" id="login-feedback" role="status"></p>
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

        <button type="button" class="btn btn-primary" style="margin-top: 16px;" onclick="simulateTransfer()">Transfer $250 to Savings</button>
        <p class="feedback" id="account-feedback" role="status"></p>
      </div>

    </div>

  </div>

  <section class="bank-section" id="personal">
    <div class="section-heading"><h2>Banking for your everyday</h2><p>Simple ways to manage today and plan for what comes next.</p></div>
    <div class="product-grid">
      <article class="product-card"><div class="icon" aria-hidden="true">&#9679;</div><h3>Everyday Checking</h3><p>Make purchases, pay bills, and keep your daily finances together.</p><a href="#online-banking">Manage online &rarr;</a></article>
      <article class="product-card"><div class="icon" aria-hidden="true">&#10022;</div><h3>Personal Savings</h3><p>Set aside money for the goals that matter to you.</p><a href="#online-banking">View accounts &rarr;</a></article>
      <article class="product-card" id="lending"><div class="icon" aria-hidden="true">&#8962;</div><h3>Home Lending</h3><p>Explore financing options for your next place to call home.</p><a href="#support">Talk with us &rarr;</a></article>
    </div>
  </section>

  <section class="bank-section" id="business">
    <div class="section-heading"><h2>For your business</h2><p>Banking tools and personal support for the work you do.</p></div>
    <div class="product-grid">
      <article class="product-card"><h3>Business Checking</h3><p>Keep payments and operating funds organized.</p></article>
      <article class="product-card"><h3>Cash Management</h3><p>Stay on top of incoming and outgoing funds.</p></article>
      <article class="product-card"><h3>Business Lending</h3><p>Discuss financing for equipment, growth, and working capital.</p></article>
    </div>
  </section>

  <section class="bank-section" id="locations">
    <div class="branch-card">
      <div><h2>Find a branch near you</h2><p>Search for a neighborhood or location to see nearby banking offices.</p></div>
      <div>
        <form class="search-row" onsubmit="searchBranches(event)">
          <input id="branch-query" type="search" aria-label="Search branches" placeholder="City, neighborhood, or ZIP code" required />
          <button class="btn btn-primary btn-action" type="submit">Search</button>
        </form>
        <div id="branch-results" aria-live="polite"></div>
      </div>
    </div>
  </section>

  <footer>
    <div class="footer-links">
      <a href="#personal">Personal Banking</a>
      <a href="#business">Business Banking</a>
      <a href="#locations">Locations</a>
    </div>
    <p id="support">&copy; 2026 First Heritage Community Bank. Illustrative website only; no real accounts, payments, or deposit insurance.</p>
  </footer>

  <script>
    let demoSession = '';
    async function refreshDemoStatus() {
      try {
        const res = await fetch('/bank/api/demo/status', { cache: 'no-store' });
        const state = await res.json();
        const totals = state.totals || {};
        document.getElementById('stat-allowed').innerText = totals.allowed || 0;
        document.getElementById('stat-attacks').innerText = totals.attack_denied || 0;
        document.getElementById('stat-blocked').innerText = totals.blocked || 0;
        document.getElementById('stat-sources').innerText = state.active_blocks || 0;
        const remaining = state.remaining_seconds || 0;
        document.getElementById('demo-clock').innerText = remaining
          ? 'Traffic stream: ' + Math.floor(remaining / 60) + ':' + String(remaining % 60).padStart(2, '0') + ' remaining'
          : 'Traffic stream complete or waiting';
        const feed = document.getElementById('demo-feed');
        feed.replaceChildren();
        for (const event of [...(state.recent_controls || []).slice(0, 6), ...(state.recent_events || []).filter(e => e.outcome === 'allowed').slice(0, 6)]) {
          const line = document.createElement('div');
          line.innerText = event.outcome.toUpperCase() + ' · ' + event.source_ip + ' · ' + event.detail;
          feed.appendChild(line);
        }
      } catch (_) {
        document.getElementById('demo-clock').innerText = 'Gateway status unavailable';
      }
    }
    refreshDemoStatus();
    setInterval(refreshDemoStatus, 2000);

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
          demoSession = data.session_id;
          document.getElementById('login-view').style.display = 'none';
          document.getElementById('account-view').style.display = 'block';
          showResult('Fictional customer signed in. The normal request was allowed and recorded.');
        } else {
          showResult('Login rejected: ' + (data.detail || data.message || 'Invalid credentials'));
        }
      } catch (err) {
        btn.innerText = 'Sign In to Accounts';
        showResult('Network error: ' + err.message);
      }
    }

    function handleLogout() {
      demoSession = '';
      document.getElementById('account-view').style.display = 'none';
      document.getElementById('login-view').style.display = 'block';
    }

    async function simulateTransfer() {
      const res = await fetch('/bank/api/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Bank-Demo-Session': demoSession },
        body: JSON.stringify({ to_account: '9021', amount: 250.00 })
      });
      const data = await res.json();
      showResult('Fictional transfer result: ' + JSON.stringify(data, null, 2));
    }

    function setPayload(txt) {
      document.getElementById('exploit-input').value = txt;
    }

    async function runSearchExploit() {
      const q = document.getElementById('exploit-input').value;
      showResult('Sending synthetic query from 203.0.113.250...');
      const res = await fetch('/bank/api/search?q=' + encodeURIComponent(q), { headers: { 'X-Demo-Source-IP': '203.0.113.250' } });
      const data = await res.json();
      showResult(JSON.stringify(data, null, 2));
    }

    async function triggerTreasuryDecoy() {
      showResult('Probing fictional treasury canary from 203.0.113.251...');
      const res = await fetch('/bank/api/admin/treasury-keys', { headers: { 'X-Demo-Source-IP': '203.0.113.251' } });
      const data = await res.json();
      showResult('Gateway response: ' + JSON.stringify(data, null, 2));
    }

    async function triggerCustomerDecoy() {
      showResult('Probing fictional customer export from 203.0.113.252...');
      const res = await fetch('/bank/api/customers/export', { headers: { 'X-Demo-Source-IP': '203.0.113.252' } });
      const data = await res.json();
      showResult('Gateway response: ' + JSON.stringify(data, null, 2));
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
