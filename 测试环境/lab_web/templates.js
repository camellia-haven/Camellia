'use strict';

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function layout(title, body, options = {}) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Northstar Books</title>
  <style>
    :root {
      color: #1f2933;
      background: #f4f1ea;
      font-family: "Segoe UI", Arial, sans-serif;
      --ink: #1f2933;
      --muted: #66727e;
      --line: #d7d1c5;
      --paper: #fffdf8;
      --accent: #9d3f2f;
      --accent-dark: #713024;
      --green: #315d46;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: #f4f1ea; color: var(--ink); }
    a { color: var(--accent-dark); }
    header {
      background: #22313a;
      color: white;
      border-bottom: 4px solid #c58438;
    }
    .bar {
      width: min(1080px, calc(100% - 32px));
      min-height: 68px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }
    .brand { color: white; font: 700 22px Georgia, serif; text-decoration: none; }
    nav { display: flex; flex-wrap: wrap; gap: 16px; }
    nav a { color: #f7f3e9; text-decoration: none; font-size: 14px; }
    nav a:hover { color: #f2c97d; }
    main { width: min(1080px, calc(100% - 32px)); margin: 30px auto 46px; }
    h1, h2, h3 { font-family: Georgia, serif; line-height: 1.18; }
    h1 { font-size: clamp(30px, 5vw, 48px); margin: 0 0 12px; }
    h2 { font-size: 25px; margin-top: 0; }
    p { line-height: 1.65; }
    .search {
      display: flex;
      margin: 24px 0 28px;
      max-width: 640px;
      border: 1px solid var(--line);
      background: white;
    }
    .search input {
      flex: 1;
      min-width: 0;
      padding: 12px 14px;
      border: 0;
      font: inherit;
    }
    .search button, .button {
      border: 0;
      background: var(--accent);
      color: white;
      padding: 11px 18px;
      font: 600 14px inherit;
      text-decoration: none;
      cursor: pointer;
    }
    .search button:hover, .button:hover { background: var(--accent-dark); }
    .section-head {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
      border-bottom: 1px solid var(--line);
      margin-bottom: 18px;
    }
    .section-head p { color: var(--muted); margin: 0 0 12px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
    }
    article.book {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--paper);
      padding: 18px;
      min-height: 220px;
      display: flex;
      flex-direction: column;
    }
    .genre { color: var(--accent-dark); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .book h3 { margin: 8px 0 4px; font-size: 21px; }
    .author { color: var(--muted); margin: 0 0 12px; font-size: 14px; }
    .summary { flex: 1; font-size: 14px; color: #46515b; }
    .meta { display: flex; justify-content: space-between; margin-top: 16px; font-weight: 700; }
    .panel {
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 24px;
    }
    .panel.narrow { max-width: 520px; }
    .notice { border-left: 4px solid var(--accent); padding-left: 14px; }
    .error { border-color: #b42318; border-left: 4px solid #b42318; }
    pre {
      overflow-x: auto;
      padding: 16px;
      background: #1f2933;
      color: #e8edf0;
      border-radius: 6px;
      line-height: 1.55;
    }
    label { display: block; margin: 14px 0 6px; font-weight: 600; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #b7b0a4;
      border-radius: 4px;
      font: inherit;
    }
    .muted { color: var(--muted); }
    footer {
      border-top: 1px solid var(--line);
      padding: 22px 16px 30px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }
    @media (max-width: 780px) {
      .bar { align-items: flex-start; flex-direction: column; padding: 16px 0; gap: 10px; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <a class="brand" href="/">Northstar Books</a>
      <nav>
        <a href="/catalog?genre=fiction">Fiction</a>
        <a href="/catalog?genre=history">History</a>
        <a href="/catalog?genre=technology">Technology</a>
        <a href="/about">About</a>
        <a href="/login">Staff login</a>
      </nav>
    </div>
  </header>
  <main>${body}</main>
  <footer>
    Northstar Books &middot; 18 Harbor Lane &middot;
    <a href="/download?file=guide.txt">Store guide</a> &middot;
    <a href="/status/host?host=127.0.0.1">Service status</a>
  </footer>
</body>
</html>`;
}

function bookCard(book) {
  return `<article class="book">
    <span class="genre">Staff selection</span>
    <h3>${escapeHtml(book.title)}</h3>
    <p class="author">${escapeHtml(book.author)}</p>
    <p class="summary">${escapeHtml(book.summary)}</p>
    <div class="meta"><span>$${Number(book.price).toFixed(2)}</span><span>${book.stock} in stock</span></div>
  </article>`;
}

function homePage(books, activeGenre = 'all') {
  const heading = activeGenre === 'all'
    ? 'Books chosen for curious readers'
    : `Browsing ${escapeHtml(activeGenre)}`;
  const contents = books.length
    ? books.map(bookCard).join('')
    : '<div class="panel"><p>No books matched this shelf.</p></div>';

  return layout(
    'Independent bookstore',
    `<section>
      <h1>${heading}</h1>
      <p class="muted">New arrivals, local history, practical guides, and stories for younger readers.</p>
      <form class="search" action="/search" method="get">
        <input type="search" name="q" placeholder="Search by title, author, or topic" aria-label="Search books">
        <button type="submit">Search</button>
      </form>
    </section>
    <section>
      <div class="section-head">
        <h2>${activeGenre === 'all' ? 'Featured this week' : 'Shelf selection'}</h2>
        <p>${books.length} title${books.length === 1 ? '' : 's'}</p>
      </div>
      <div class="grid">${contents}</div>
    </section>`,
  );
}

function searchPage(term, books) {
  const results = books.length
    ? `<div class="grid">${books.map(bookCard).join('')}</div>`
    : '<div class="panel"><p>No matching titles were found.</p></div>';

  return layout(
    'Search',
    `<section class="panel">
      <h1>Search results</h1>
      <p>Showing matches for: <strong>${term}</strong></p>
      <form class="search" action="/search" method="get">
        <input type="search" name="q" value="${escapeHtml(term)}" aria-label="Search books">
        <button type="submit">Search again</button>
      </form>
    </section>
    <section style="margin-top:22px">${results}</section>`,
  );
}

function loginPage(errorMessage = '') {
  const error = errorMessage
    ? `<p class="notice error">${escapeHtml(errorMessage)}</p>`
    : '';
  return layout(
    'Staff login',
    `<section class="panel narrow">
      <h1>Staff login</h1>
      <p class="muted">Use your Northstar Books staff account to open the store dashboard.</p>
      ${error}
      <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="northstar-login-token">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <p><button class="button" type="submit">Sign in</button></p>
      </form>
    </section>`,
  );
}

function dashboardPage(user) {
  return layout(
    'Dashboard',
    `<section class="panel">
      <p class="muted">Staff dashboard</p>
      <h1>Welcome back, ${escapeHtml(user.display_name)}</h1>
      <p>Today&apos;s stock count is available from the catalog service.</p>
      <p><a href="/logout">Log out</a></p>
    </section>`,
  );
}

function statusPage(host, output) {
  return layout(
    'Service status',
    `<section class="panel">
      <p class="muted">Internal diagnostics</p>
      <h1>Host lookup</h1>
      <form class="search" action="/status/host" method="get">
        <input type="text" name="host" value="${escapeHtml(host)}" aria-label="Host name">
        <button type="submit">Check host</button>
      </form>
      <pre>${escapeHtml(output)}</pre>
    </section>`,
  );
}

function messagePage(title, message) {
  return layout(
    title,
    `<section class="panel">
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
      <p><a href="/">Return to the store</a></p>
    </section>`,
  );
}

function errorPage(title, detail) {
  return layout(
    title,
    `<section class="panel error">
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(detail)}</p>
      <p><a href="/">Return to the store</a></p>
    </section>`,
  );
}

module.exports = {
  dashboardPage,
  errorPage,
  homePage,
  loginPage,
  messagePage,
  searchPage,
  statusPage,
};
