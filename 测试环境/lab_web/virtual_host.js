'use strict';

const fs = require('node:fs');
const path = require('node:path');

const HOST_ROOT = path.resolve(__dirname, 'virtual_host');
const PUBLIC_WEB_ROOT = '/opt/bookstore/releases/current/public/files';
const CONTENT_TYPES = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.csv', 'text/csv; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ini', 'text/plain; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
]);

function requestedVirtualPath(requestedName) {
  let value = String(requestedName || 'guide.txt').replaceAll('\\', '/');

  if (/^[A-Za-z]:\//.test(value)) {
    value = value.slice(2);
  }

  return path.posix.resolve(PUBLIC_WEB_ROOT, value);
}

function readHostFile(requestedName) {
  const virtualPath = requestedVirtualPath(requestedName);
  const diskPath = path.resolve(HOST_ROOT, virtualPath.slice(1));
  const content = fs.readFileSync(diskPath);
  const extension = path.extname(diskPath).toLowerCase();

  return {
    content,
    contentType: CONTENT_TYPES.get(extension) || 'application/octet-stream',
    name: path.basename(diskPath),
    virtualPath,
  };
}

module.exports = { readHostFile, requestedVirtualPath };
