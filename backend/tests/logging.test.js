// Logging tests: spawn the real server, check log lines are JSON,
// carry the score band, and never contain the submitted input.
// Run: node tests/logging.test.js
'use strict';
const { spawn } = require('child_process');
const path = require('path');

const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

async function main() {
  let passed = 0, failed = 0;
  function check(name, cond, extra) {
    if (cond) { passed++; console.log('PASS ' + name); }
    else { failed++; console.log('FAIL ' + name + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')); }
  }

  const marker = 'MARKER_SECRET_9f3a7b';
  const server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: Object.assign({}, process.env, {
      PORT: '3199', REDIRECT_ENABLED: '0', URLHAUS_ENABLED: '0'
    })
  });
  let out = '';
  server.stdout.on('data', function (d) { out += d.toString(); });
  server.stderr.on('data', function () {});

  for (let i = 0; i < 100 && out.indexOf('listening on port 3199') === -1; i++) {
    await sleep(100);
  }
  const base = 'http://localhost:3199';
  const ok = await fetch(base + '/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: marker + ' please verify http://example.com' })
  });
  await ok.json();
  const bad = await fetch(base + '/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  await bad.json();
  await sleep(400);
  server.kill('SIGTERM');
  await Promise.race([
    new Promise(function (r) { server.on('exit', r); }),
    sleep(3000)
  ]);

  const logs = out.split('\n')
    .filter(function (l) { return l.trim().startsWith('{'); })
    .map(function (l) { try { return JSON.parse(l); } catch (e) { return null; } })
    .filter(Boolean);
  const analyzeOk = logs.find(function (l) { return l.path === '/api/analyze' && l.status === 200; });
  check('analyze request logged as JSON with score band',
    !!analyzeOk && typeof analyzeOk.level === 'string' && typeof analyzeOk.score === 'number',
    analyzeOk);
  check('no log line contains the submitted input', out.indexOf(marker) === -1);
  const errLog = logs.find(function (l) { return l.path === '/api/analyze' && l.status === 400; });
  check('error request logged with error code',
    !!errLog && errLog.error === 'MISSING_INPUT', errLog);

  console.log('\n' + passed + ' passed, ' + failed + ' failed.');
  process.exit(failed ? 1 : 0);
}

main().catch(function (e) { console.error('ERROR: ' + e.message); process.exit(1); });
