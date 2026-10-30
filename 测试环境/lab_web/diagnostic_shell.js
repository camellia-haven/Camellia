'use strict';

const net = require('node:net');

function tokenize(commandLine) {
  const tokens = [];
  const expression = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = expression.exec(commandLine)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }
  return tokens;
}

function identityOutput() {
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
  const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;
  return `uid=${uid}(bookstore) gid=${gid}(bookstore) groups=${gid}(bookstore)`;
}

function runCommand(commandLine) {
  const tokens = tokenize(commandLine.trim());
  if (tokens.length === 0) {
    return '';
  }

  const command = tokens[0].toLowerCase();
  const args = tokens.slice(1);

  if (command === 'lookup') {
    const target = args[0] || '127.0.0.1';
    const address = net.isIP(target) ? target : '203.0.113.10';
    return `Name:    ${target}\nAddress: ${address}`;
  }

  if (command === 'id') {
    return identityOutput();
  }

  if (command === 'whoami') {
    return 'bookstore';
  }

  if (command === 'hostname') {
    return 'bookstore-web-01';
  }

  if (command === 'date') {
    return new Date().toISOString();
  }

  if (command === 'echo') {
    return args.join(' ');
  }

  return `bookstore-shell: command not found: ${command}`;
}

function executeScript(script) {
  return script
    .split(/[;\r\n|]+/)
    .map((command) => command.trim())
    .filter(Boolean)
    .map(runCommand)
    .filter(Boolean)
    .join('\n');
}

function expandSubstitutions(script) {
  return script.replace(/\$\(([^)]*)\)|`([^`]*)`/g, (_match, modern, legacy) => {
    return executeScript(modern ?? legacy);
  });
}

function runHostLookup(host) {
  // The legacy diagnostics controller builds one shell string from user input.
  const script = expandSubstitutions(`lookup ${host}`);
  return executeScript(script);
}

module.exports = { runHostLookup };
