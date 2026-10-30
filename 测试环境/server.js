'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const { URL } = require('node:url');

const { createStore } = require('./lab_web/database');
const { runHostLookup } = require('./lab_web/diagnostic_shell');
const {
  dashboardPage,
  errorPage,
  homePage,
  loginPage,
  messagePage,
  searchPage,
  statusPage,
} = require('./lab_web/templates');
const { readHostFile } = require('./lab_web/virtual_host');

const HOST = '127.0.0.1';
const DEFAULT_PORT = 8088;
const store = createStore();
const sessions = new Map();

function parsePort(argv) {
  const index = argv.indexOf('--port');
  if (index === -1) {
    return DEFAULT_PORT;
  }
  const value = Number.parseInt(argv[index + 1], 10);
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    throw new Error('--port must be an integer between 0 and 65535');
  }
  return value;
}

function sendHtml(response, statusCode, body, extraHeaders = {}) {
  const payload = Buffer.from(body, 'utf8');
  response.writeHead(statusCode, {
    'Cache-Control': 'no-store',
    'Content-Length': payload.length,
    'Content-Type': 'text/html; charset=utf-8',
    ...extraHeaders,
  });
  response.end(payload);
}

function sendFile(response, file) {
  response.writeHead(200, {
    'Cache-Control': 'no-store',
    'Content-Disposition': `inline; filename="${file.name}"`,
    'Content-Length': file.content.length,
    'Content-Type': file.contentType,
  });
  response.end(file.content);
}

function redirect(response, location, headers = {}) {
  response.writeHead(302, {
    'Content-Length': '0',
    Location: location,
    ...headers,
  });
  response.end();
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(new Error('Request body is too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

function parseCookie(request) {
  const header = request.headers.cookie || '';
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf('=');
        if (separator === -1) {
          return [part, ''];
        }
        return [part.slice(0, separator), part.slice(separator + 1)];
      }),
  );
}

function sessionFor(request) {
  const token = parseCookie(request).bookstore_session;
  return token ? sessions.get(token) : null;
}

async function handleRequest(request, response) {
  const requestUrl = new URL(
    request.url,
    `http://${request.headers.host || `${HOST}:${DEFAULT_PORT}`}`,
  );
  const pathname = requestUrl.pathname;
  const query = requestUrl.searchParams;

  if (request.method === 'GET' && pathname === '/') {
    sendHtml(response, 200, homePage(store.listFeaturedBooks()));
    return;
  }

  if (request.method === 'GET' && pathname === '/healthz') {
    response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('ok');
    return;
  }

  if (request.method === 'GET' && pathname === '/catalog') {
    const genre = query.get('genre') || 'all';
    try {
      const books = store.findBooksByGenre(genre);
      sendHtml(response, 200, homePage(books, genre));
    } catch (error) {
      sendHtml(
        response,
        500,
        errorPage(
          'Catalog is temporarily unavailable',
          `SQLite error while loading catalog: ${error.message}`,
        ),
      );
    }
    return;
  }

  if (request.method === 'GET' && pathname === '/search') {
    const term = query.get('q') || '';
    const books = store.searchBooks(term);
    sendHtml(response, 200, searchPage(term, books));
    return;
  }

  if (request.method === 'GET' && pathname === '/download') {
    const requestedFile = query.get('file') || 'guide.txt';
    try {
      sendFile(response, readHostFile(requestedFile));
    } catch {
      sendHtml(response, 404, messagePage('Document not found', 'The requested document is unavailable.'));
    }
    return;
  }

  if (request.method === 'GET' && pathname === '/status/host') {
    const host = query.get('host') || '127.0.0.1';
    const output = runHostLookup(host);
    sendHtml(response, 200, statusPage(host, output));
    return;
  }

  if (request.method === 'GET' && pathname === '/login') {
    sendHtml(response, 200, loginPage());
    return;
  }

  if (request.method === 'POST' && pathname === '/login') {
    try {
      const form = new URLSearchParams(await readBody(request));
      const username = form.get('username') || '';
      const password = form.get('password') || '';
      const user = store.authenticate(username, password);
      if (!user) {
        sendHtml(
          response,
          401,
          loginPage('Invalid username or password. Please try again.'),
        );
        return;
      }

      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, user);
      redirect(response, '/dashboard', {
        'Set-Cookie': `bookstore_session=${token}; HttpOnly; SameSite=Lax; Path=/`,
      });
    } catch {
      sendHtml(response, 400, messagePage('Bad request', 'The login request could not be processed.'));
    }
    return;
  }

  if (request.method === 'GET' && pathname === '/dashboard') {
    const user = sessionFor(request);
    if (!user) {
      redirect(response, '/login');
      return;
    }
    sendHtml(response, 200, dashboardPage(user));
    return;
  }

  if (request.method === 'GET' && pathname === '/logout') {
    const token = parseCookie(request).bookstore_session;
    if (token) {
      sessions.delete(token);
    }
    redirect(response, '/login', {
      'Set-Cookie': 'bookstore_session=; HttpOnly; Max-Age=0; Path=/',
    });
    return;
  }

  if (request.method === 'GET' && pathname === '/about') {
    sendHtml(
      response,
      200,
      messagePage(
        'About Northstar Books',
        'Northstar Books is a small independent bookstore serving the local community.',
      ),
    );
    return;
  }

  sendHtml(response, 404, messagePage('Page not found', 'This page does not exist.'));
}

function createServer(port = DEFAULT_PORT) {
  const server = http.createServer((request, response) => {
    handleRequest(request, response).catch((error) => {
      if (!response.headersSent) {
        sendHtml(response, 500, errorPage('Server error', 'The application could not process this request.'));
      } else {
        response.destroy();
      }
      if (process.env.LAB_DEBUG === '1') {
        console.error(error);
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, HOST, () => resolve(server));
  });
}

async function main() {
  const port = parsePort(process.argv.slice(2));
  const server = await createServer(port);
  const actualPort = server.address().port;
  console.log(`Northstar Books lab: http://${HOST}:${actualPort}`);
  console.log('Scope: local-only educational environment; listening on 127.0.0.1.');

  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = { HOST, createServer };
