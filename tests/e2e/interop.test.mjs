// End-to-end interoperability test: the Laravel workbench application (this
// package) against the reference service of the Site Portrait specification.
//
//   SP_REFERENCE_DIR=../site-portrait node --test tests/e2e/interop.test.mjs
//
// Requires PHP, Composer dependencies, and a checkout of the specification
// repository (bin/lib/*.mjs, docs/schema, and its node_modules for ajv).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const REF = path.resolve(process.env.SP_REFERENCE_DIR ?? path.join(ROOT, '../site-portrait'));
const SITE_PORT = 8765; // Must match APP_URL in testbench.yaml.
const SITE = `http://127.0.0.1:${SITE_PORT}`;

const ref = (p) => import(pathToFileURL(path.join(REF, p)).href);
const { State } = await ref('bin/lib/state.mjs');
const { createService } = await ref('bin/lib/service.mjs');
const { signedFetch } = await ref('bin/lib/client.mjs');

let service;
let state;
let site;
const logs = [];

// Asynchronous on purpose: the reference service runs in this process and
// must keep answering while artisan talks to it.
async function artisan(...args) {
  const { stdout } = await promisify(execFile)('php', ['vendor/bin/testbench', ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  return stdout;
}

async function freePort() {
  const probe = http.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  return port;
}

async function waitFor(fn, timeout = 30_000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const v = await fn().catch(() => null);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Timed out');
}

async function validate(schemaFile, data) {
  const { default: Ajv } = await ref('node_modules/ajv/dist/2020.js');
  const { default: addFormats } = await ref('node_modules/ajv-formats/dist/index.js');
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const schema = JSON.parse(fs.readFileSync(path.join(REF, 'docs/schema', schemaFile), 'utf8'));
  return ajv.validate(schema, data) ? [] : ajv.errors;
}

/** Runs site-portrait:pair, then plays the administrator's browser. */
async function pair(scopes = 'laravel,packages,server,database,storage,users_counts') {
  const out = await artisan('site-portrait:pair', service.url, `--scopes=${scopes}`, '--yes');
  const url = out.match(/^\s*(http\S+\/authorize\?\S+)\s*$/m)?.[1];
  assert.ok(url, `No authorization URL in:\n${out}`);

  const approve = await fetch(url, { redirect: 'manual' });
  assert.equal(approve.status, 302, 'the reference service auto-approves');
  const callback = approve.headers.get('location');
  assert.ok(callback.startsWith(`${SITE}/site-portrait/callback?token=`), callback);

  const page = await fetch(callback, { redirect: 'manual' });
  const html = await page.text();
  assert.equal(page.status, 200, html);
  assert.match(html, /now connected/);

  const pairing = await waitFor(async () => state.pairing());
  assert.equal(await service.confirmations.get(pairing.pairing_id), true, 'the service confirmed the pairing through /status');
  return state.pairing(pairing.pairing_id);
}

before(async () => {
  assert.ok(fs.existsSync(path.join(REF, 'bin/lib/service.mjs')), `Reference repository not found in ${REF} (set SP_REFERENCE_DIR)`);
  await artisan('workbench:build');

  site = spawn('php', ['vendor/bin/testbench', 'serve', '--host=127.0.0.1', `--port=${SITE_PORT}`, '--no-reload'], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], detached: true, env: { ...process.env, PHP_CLI_SERVER_WORKERS: '4' },
  });
  site.stdout.on('data', (d) => logs.push(String(d)));
  site.stderr.on('data', (d) => logs.push(String(d)));
  await waitFor(async () => (await fetch(`${SITE}/site-portrait/v1/status`)).status === 404);

  const port = await freePort();
  state = new State(fs.mkdtempSync(path.join(os.tmpdir(), 'sp-laravel-e2e-')));
  const url = `http://127.0.0.1:${port}`;
  const created = createService({ state, publicUrl: url, autoApprove: true, log: (m) => logs.push(`[service] ${m}`) });
  await new Promise((r) => created.server.listen(port, '127.0.0.1', r));
  service = { url, ...created };
});

after(async () => {
  await new Promise((r) => service?.server.close(r));
  try {
    process.kill(-site.pid, 'SIGTERM');
  } catch {
    // Already stopped.
  }
  if (process.env.SP_E2E_LOGS) console.log(logs.join(''));
});

test('pairing, status, portrait, replay, key rotations and revocations', async () => {
  // Without pairing, the API does not exist.
  const none = await fetch(`${SITE}/site-portrait/v1/status`);
  assert.equal(none.status, 404);
  assert.equal((await none.json()).code, 'rest_no_route');

  let pairing = await pair();
  assert.deepEqual(pairing.endpoints, {
    status: `${SITE}/site-portrait/v1/status`,
    portrait: `${SITE}/site-portrait/v1/portrait`,
    revoke: `${SITE}/site-portrait/v1/revoke`,
  });

  // /status, signed and bound to the request.
  const status = await signedFetch(state, pairing, 'status');
  assert.equal(status.status, 200);
  assert.ok(status.kid, 'response signature verified');
  assert.equal(status.headers['site-portrait-protocol'], '1');
  assert.equal(status.json.pairing_id, pairing.pairing_id);
  assert.equal(status.json.platform.name, 'laravel');
  assert.deepEqual(status.json.scopes_granted, ['laravel', 'packages', 'server', 'database', 'storage', 'users_counts']);

  // Full portrait, valid against the schema of the specification.
  const portrait = await signedFetch(state, pairing, 'portrait', { query: { scopes: 'laravel,packages,server,database,storage,users_counts' } });
  assert.equal(portrait.status, 200, portrait.text);
  assert.ok(portrait.kid);
  assert.deepEqual(await validate('portrait-v1.schema.json', portrait.json), []);
  assert.equal(portrait.json.data.laravel.environment_type, 'local');
  assert.equal(portrait.json.data.database.engine, 'sqlite');

  // WordPress scopes are unknown here.
  const wp = await signedFetch(state, pairing, 'portrait', { query: { scopes: 'core,plugins' } });
  assert.equal(wp.status, 400);
  assert.equal(wp.json.code, 'site_portrait_invalid_scope');

  // Replay of a captured request.
  const replay = await signedFetch(state, pairing, 'status', { replayHeaders: status.sent });
  assert.equal(replay.status, 401);
  assert.equal(replay.json.code, 'site_portrait_replay');

  // Scope narrowing by the administrator, without re-pairing.
  await artisan('site-portrait:scopes', '--deny=packages');
  const narrowed = await signedFetch(state, pairing, 'portrait', { query: { scopes: 'server,packages' } });
  assert.equal(narrowed.status, 200);
  assert.deepEqual(narrowed.json.scopes_returned, ['server']);
  assert.deepEqual(narrowed.json.scopes_denied, ['packages']);

  // Service key rotation: the site re-reads discovery and pins the endorsed key.
  state.rotateKey();
  const afterServiceRotation = await signedFetch(state, pairing, 'status');
  assert.equal(afterServiceRotation.status, 200, afterServiceRotation.text);

  // Site key rotation: the client learns the endorsed key from /status.
  await artisan('site-portrait:rotate-key');
  const afterSiteRotation = await signedFetch(state, state.pairing(pairing.pairing_id), 'status');
  assert.equal(afterSiteRotation.status, 200);
  assert.notEqual(afterSiteRotation.kid, status.kid);

  // Service-initiated revocation.
  pairing = state.pairing(pairing.pairing_id);
  const revoked = await signedFetch(state, pairing, 'revoke', { method: 'POST', body: { pairing_id: pairing.pairing_id, reason: 'account_closed' } });
  assert.equal(revoked.status, 200, revoked.text);
  assert.ok(revoked.kid);
  assert.deepEqual(revoked.json, { revoked: true });
  assert.equal((await signedFetch(state, pairing, 'status')).status, 404);
  state.deletePairing(pairing.pairing_id);

  // Site-initiated revocation notice.
  const second = await pair('server,database');
  const out = await artisan('site-portrait:disconnect', '--force');
  assert.match(out, /service was notified/);
  assert.equal(state.pairing(second.pairing_id), null, 'the service deleted the pairing');
});
