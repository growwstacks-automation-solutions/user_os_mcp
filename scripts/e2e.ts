// scripts/e2e.ts — `npm run e2e` (end-to-end test of user-os-mcp, TEST BRANCH ONLY)
//
// Calls the REAL Worker (src/index.ts fetch) in-process with real MCP JSON-RPC
// requests, so every call goes through the real sign-in, role gate, zod
// validation, tool code, Postgres RLS and the upload endpoint.
//
// Only CLERK is simulated: the script mints its own RS256 key, points
// CLERK_ISSUER / CLERK_JWKS_URL (in memory) at a fake issuer, signs access tokens
// for real OS users, and answers the Clerk Backend API user lookup with that
// user's real email. All other network traffic (Neon) is real.
//
// SAFETY
//   * Refuses to run unless the DATABASE_URL host contains "ep-curly-fog" (and
//     never if it contains "ep-morning-meadow"). Prints the host masked.
//   * Never prints secrets or emails.
//   * Every record it creates is named "[MCP-TEST] …", is written to a manifest
//     (.wrangler/e2e-manifest.json), and is archived in the cleanup phase, which
//     always runs. `npm run e2e -- --cleanup-only` re-runs just the cleanup.
//   * Notification safety: every test task's ONLY assignee/manager is the test
//     developer; comments are posted by the task's creator (sender is excluded).
//     Two approved exceptions, where the only legal assignee is the actor:
//     the operations user's self-assigned task, and the pm's self-assign.
//
// Never imported by src/.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { neon } from '@neondatabase/serverless';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import worker from '../src/index';
import type { Env } from '../src/db';
import { NEVER_RETURN_FIELDS, toolsForRole } from '../src/permissions';

// ---------------------------------------------------------------------------
// Setup + safety
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const CLEANUP_ONLY = args.includes('--cleanup-only');
const DEV_BASE = (args[args.indexOf('--dev-base') + 1] && args.includes('--dev-base'))
  ? args[args.indexOf('--dev-base') + 1] : 'http://127.0.0.1:8788';
const MANIFEST = '.wrangler/e2e-manifest.json';
const PREFIX = '[MCP-TEST]';
const CLEANUP_REASON = 'MCP e2e test cleanup';
const DEVELOPER_ID = 'bd860a54-7846-41e0-84bf-bbf0e2f3dad0'; // U-0068, the only test assignee/manager
const SERVICE_IDS = ['00000000-0000-0000-0000-0000000000fe', '00000000-0000-0000-0000-0000000000ff'];

const vars: Record<string, string> = Object.fromEntries(
  readFileSync('.dev.vars', 'utf8').split(/\r?\n/)
    .map((l) => l.match(/^\s*([A-Z_]+)\s*=\s*(.*)$/)).filter((m): m is RegExpMatchArray => !!m)
    .map((m) => [m[1], m[2].trim().replace(/^["']|["']$/g, '')]),
);
const dbHost = new URL(vars.DATABASE_URL).hostname;
if (!dbHost.includes('ep-curly-fog') || dbHost.includes('ep-morning-meadow')) {
  console.error('REFUSING: DATABASE_URL is not the Neon test branch (ep-curly-fog).');
  process.exit(2);
}
console.log(`Database host: ${dbHost.replace(/^(ep-[a-z]+-[a-z]+)-[a-z0-9]+/, '$1-****')}`);
if (!vars.UPLOAD_SIGNING_KEY) { console.error('UPLOAD_SIGNING_KEY missing from .dev.vars'); process.exit(2); }

const ORIGIN = 'http://e2e.local';
const RESOURCE = `${ORIGIN}/mcp`;
const FAKE_ISSUER = 'https://e2e-fake-issuer.invalid';
const FAKE_JWKS = `${FAKE_ISSUER}/.well-known/jwks.json`;

const env: Env = {
  DATABASE_URL: vars.DATABASE_URL,
  GS_ACTOR_UID: vars.GS_ACTOR_UID,
  UPLOAD_SIGNING_KEY: vars.UPLOAD_SIGNING_KEY,
  CLERK_ISSUER: FAKE_ISSUER,
  CLERK_JWKS_URL: FAKE_JWKS,
  CLERK_SECRET_KEY: 'sk_e2e_fake_never_sent_to_clerk',
};

// Direct read-only access for setup and verification (never used for writes).
const sql = neon(vars.DATABASE_URL);
const SERVICE_UID = vars.GS_ACTOR_UID || SERVICE_IDS[1];
async function readAs<T = any>(uid: string, build: (s: typeof sql) => any): Promise<T[]> {
  const res = await sql.transaction([sql`select set_config('app.current_user_id', ${uid}, true)`, build(sql)], { readOnly: true });
  return res[1] as T[];
}

// ---------------------------------------------------------------------------
// Fake Clerk: JWKS + Backend API user lookup. Everything else passes through.
// ---------------------------------------------------------------------------
const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: 'e2e', alg: 'RS256', use: 'sig' }] };
const clerkUsers = new Map<string, { email: string; verified: boolean }>();
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (url.includes('ep-morning-meadow')) throw new Error('BLOCKED: production database host');
  if (url === FAKE_JWKS) return Response.json(jwks);
  if (url === `${FAKE_ISSUER}/.well-known/oauth-authorization-server`) {
    return Response.json({ issuer: FAKE_ISSUER, authorization_endpoint: `${FAKE_ISSUER}/oauth/authorize`, token_endpoint: `${FAKE_ISSUER}/oauth/token` });
  }
  if (url.startsWith('https://api.clerk.com/')) {
    const sub = decodeURIComponent(url.split('/v1/users/')[1] ?? '');
    const u = clerkUsers.get(sub);
    if (!u) return Response.json({ errors: [{ code: 'resource_not_found' }] }, { status: 404 });
    return Response.json({
      primary_email_address_id: 'idn_1',
      email_addresses: [{ id: 'idn_1', email_address: u.email, verification: { status: u.verified ? 'verified' : 'unverified' } }],
    });
  }
  return realFetch(input, init);
}) as typeof fetch;

type TokenOpts = { iss?: string; aud?: string | null; clientId?: string | null; scope?: string | null; expSecs?: number; hs256?: boolean };
async function mintToken(sub: string, o: TokenOpts = {}): Promise<string> {
  const claims: Record<string, unknown> = {};
  if (o.clientId !== null) claims.client_id = o.clientId ?? 'e2e-client';
  if (o.scope !== null) claims.scope = o.scope ?? 'email profile';
  let jwt = new SignJWT(claims).setSubject(sub).setIssuer(o.iss ?? FAKE_ISSUER).setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + (o.expSecs ?? 600));
  if (o.aud !== null) jwt = jwt.setAudience(o.aud ?? RESOURCE);
  if (o.hs256) return jwt.setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode('x'.repeat(32)));
  return jwt.setProtectedHeader({ alg: 'RS256', kid: 'e2e' }).sign(privateKey);
}

// ---------------------------------------------------------------------------
// MCP client over the in-process Worker
// ---------------------------------------------------------------------------
let rpcId = 0;
async function rpc(token: string | null, method: string, params: unknown = {}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
  if (token !== null) headers.Authorization = `Bearer ${token}`;
  const res = await worker.fetch(new Request(RESOURCE, {
    method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  }), env);
  const text = await res.text();
  let body: any = null;
  try {
    if ((res.headers.get('content-type') ?? '').includes('text/event-stream')) {
      const data = text.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim());
      body = JSON.parse(data[data.length - 1]);
    } else body = JSON.parse(text);
  } catch { body = text; }
  return { status: res.status, headers: res.headers, body };
}

type User = { role: string; id: string; display_id: string; full_name: string; email: string; sub: string; token: string };
type CallResult = { ok: boolean; data?: any; error?: string };

// Every tool output is scanned for rating fields (work_ratings values / reviewer).
const ratingLeaks: string[] = [];
let outputsScanned = 0;
function scanForRatings(tool: string, v: unknown) {
  if (Array.isArray(v)) { v.forEach((x) => scanForRatings(tool, x)); return; }
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (NEVER_RETURN_FIELDS.has(k)) ratingLeaks.push(`${tool}.${k}`);
      scanForRatings(tool, x);
    }
  }
}

async function call(u: User, name: string, a: Record<string, unknown> = {}): Promise<CallResult> {
  const r = await rpc(u.token, 'tools/call', { name, arguments: a });
  if (r.status !== 200) return { ok: false, error: `HTTP ${r.status} ${JSON.stringify(r.body)}` };
  if (r.body?.error) return { ok: false, error: r.body.error.message ?? JSON.stringify(r.body.error) };
  const res = r.body?.result;
  const text = (res?.content ?? []).map((c: any) => c.text).join('\n');
  outputsScanned += 1;
  for (const f of NEVER_RETURN_FIELDS) if (new RegExp(`"${f}"\\s*:`).test(text)) ratingLeaks.push(`${name}: "${f}" in text`);
  if (res?.isError) return { ok: false, error: text };
  try { const data = JSON.parse(text); scanForRatings(name, data); return { ok: true, data }; } catch { return { ok: true, data: text }; }
}
const hasMoney = (v: unknown): boolean => /"(price|currency)"\s*:/.test(JSON.stringify(v ?? null));

// ---------------------------------------------------------------------------
// Results + manifest
// ---------------------------------------------------------------------------
type Row = { section: string; check: string; result: 'PASS' | 'FAIL' | 'SKIP'; detail: string };
const results: Row[] = [];
function check(section: string, name: string, pass: boolean, detail = '') {
  results.push({ section, check: name, result: pass ? 'PASS' : 'FAIL', detail });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? `  — ${detail}` : ''}`);
}
function skip(section: string, name: string, why: string) {
  results.push({ section, check: name, result: 'SKIP', detail: why });
  console.log(`  SKIP  ${name}  — ${why}`);
}
const short = (s: string | undefined, n = 140) => (s ?? '').replace(/\s+/g, ' ').slice(0, n);

type Manifest = {
  records: { entity: string; id: string; by: string }[];
  joins: { kind: 'task_assignee' | 'task_manager' | 'project_member'; a: string; b: string }[];
  leftovers: { kind: string; id: string }[];
};
const manifest: Manifest = existsSync(MANIFEST) ? JSON.parse(readFileSync(MANIFEST, 'utf8')) : { records: [], joins: [], leftovers: [] };
const saveManifest = () => { mkdirSync('.wrangler', { recursive: true }); writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2)); };
function created(entity: string, id: string, by: User) { manifest.records.push({ entity, id, by: by.display_id }); saveManifest(); }

// ---------------------------------------------------------------------------
// Users: one active real user per role (read-only)
// ---------------------------------------------------------------------------
const ROLES = ['super_admin', 'admin', 'pm', 'sales', 'developer', 'internal', 'operations'];
const picked = await readAs<{ role: string; id: string; display_id: string; full_name: string; email: string }>(SERVICE_UID, (s) => s`
  SELECT DISTINCT ON (u.role) u.role::text AS role, u.id, u.display_id, u.full_name, u.email
  FROM users u
  WHERE u.archived_at IS NULL AND u.status = 'active' AND u.id::text NOT LIKE '00000000-0000-0000-0000-0000000000%'
  ORDER BY u.role, (u.id = ${DEVELOPER_ID}::uuid) DESC,
           (SELECT count(*) FROM projects p WHERE p.project_manager_id = u.id AND p.archived_at IS NULL) DESC, u.display_id`);
const users: Record<string, User> = {};
for (const p of picked) {
  const sub = `user_e2e_${p.role}`;
  clerkUsers.set(sub, { email: p.email, verified: true });
  users[p.role] = { ...p, sub, token: await mintToken(sub) };
}
const [otherDev] = await readAs<{ id: string; display_id: string }>(SERVICE_UID, (s) => s`
  SELECT id, display_id FROM users WHERE role = 'developer' AND status = 'active' AND archived_at IS NULL
    AND id <> ${DEVELOPER_ID}::uuid ORDER BY display_id LIMIT 1`);
console.log('\nTest users (real, active, test branch):');
for (const r of ROLES) console.log(`  ${r.padEnd(12)} ${users[r] ? `${users[r].display_id} ${users[r].full_name}` : '(none — role untestable)'}`);
const admin = users.admin, pm = users.pm, sales = users.sales, dev = users.developer;
const ops = users.operations, sa = users.super_admin;
if (!admin || !dev || dev.id !== DEVELOPER_ID) { console.error('Required admin/developer users not found; stopping.'); process.exit(2); }

// ---------------------------------------------------------------------------
// Cleanup (always runs)
// ---------------------------------------------------------------------------
async function cleanup() {
  console.log('\n[8] Cleanup (as admin)');
  const S = '8 Cleanup';
  for (const j of [...manifest.joins].reverse()) {
    const tool = j.kind === 'task_assignee' ? 'remove_task_assignee' : j.kind === 'task_manager' ? 'remove_task_manager' : 'remove_project_member';
    const keyA = j.kind === 'project_member' ? 'project_id' : 'task_id';
    const r = await call(admin, tool, { [keyA]: j.a, user_id: j.b });
    check(S, `${tool} ${j.a.slice(0, 8)}…`, r.ok, r.ok ? `removed=${r.data?.removed}` : short(r.error));
  }
  manifest.joins = []; saveManifest();
  const order = ['payment', 'task', 'milestone', 'project', 'deal', 'contact', 'company'];
  const failed: string[] = [];
  for (const entity of order) {
    for (const rec of manifest.records.filter((x) => x.entity === entity)) {
      const r = await call(admin, 'archive_record', { entity, id: rec.id, reason: CLEANUP_REASON });
      const already = !r.ok && /already archived/i.test(r.error ?? '');
      check(S, `archive ${entity} ${rec.id.slice(0, 8)}… (made by ${rec.by})`, r.ok || already, r.ok ? '' : short(r.error));
      if (!r.ok && !already) failed.push(`${entity} ${rec.id}`);
    }
  }
  // Verify: no live [MCP-TEST] record anywhere (read-only, as the service account).
  const [left] = await readAs(SERVICE_UID, (s) => s`SELECT
    (SELECT count(*)::int FROM companies  WHERE archived_at IS NULL AND name      LIKE '[MCP-TEST]%') AS companies,
    (SELECT count(*)::int FROM contacts   WHERE archived_at IS NULL AND full_name LIKE '[MCP-TEST]%') AS contacts,
    (SELECT count(*)::int FROM deals      WHERE archived_at IS NULL AND name      LIKE '[MCP-TEST]%') AS deals,
    (SELECT count(*)::int FROM projects   WHERE archived_at IS NULL AND name      LIKE '[MCP-TEST]%') AS projects,
    (SELECT count(*)::int FROM milestones WHERE archived_at IS NULL AND name      LIKE '[MCP-TEST]%') AS milestones,
    (SELECT count(*)::int FROM tasks      WHERE archived_at IS NULL AND title     LIKE '[MCP-TEST]%') AS tasks,
    (SELECT count(*)::int FROM payments   WHERE archived_at IS NULL AND note      LIKE '[MCP-TEST]%') AS payments`);
  const live = Object.entries(left).filter(([, n]) => Number(n) > 0);
  check(S, 'no live [MCP-TEST] records remain', live.length === 0, live.length ? JSON.stringify(left) : JSON.stringify(left));
  if (failed.length === 0 && live.length === 0) { manifest.records = []; saveManifest(); }
  return failed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
const EXPECTED: Record<string, number> = { super_admin: 48, admin: 48, pm: 48, sales: 24, developer: 18, operations: 18 };
const ids: Record<string, string> = {};

async function s1Visibility() {
  console.log('\n[1] Tool visibility');
  const S = '1 Visibility';
  for (const role of Object.keys(EXPECTED)) {
    const u = users[role];
    if (!u) { skip(S, `${role} tools/list`, 'no active user with this role'); continue; }
    const r = await rpc(u.token, 'tools/list');
    const names: string[] = (r.body?.result?.tools ?? []).map((t: any) => t.name).sort();
    const want = [...toolsForRole(role)].sort();
    const same = names.length === want.length && names.every((n, i) => n === want[i]);
    check(S, `${role} sees exactly its permissions.ts tools`, r.status === 200 && same && names.length === EXPECTED[role],
      `${names.length}/${EXPECTED[role]}${same ? '' : ` extra=[${names.filter((n) => !want.includes(n as any))}] missing=[${want.filter((n) => !names.includes(n))}]`}`);
  }
  if (users.internal) {
    const r = await rpc(users.internal.token, 'tools/list');
    check(S, 'M1 internal sign-in refused with 403 + message', r.status === 403 && /Your role \(internal\) does not have MCP access yet/.test(JSON.stringify(r.body)), `HTTP ${r.status} ${short(JSON.stringify(r.body))}`);
  } else skip(S, 'internal 403', 'no active internal user');
  for (const [u, tool] of [[dev, 'get_payments'], [ops, 'get_payments'], [ops, 'archive_record'], [sales, 'get_payments'], [sales, 'list_tasks']] as const) {
    if (!u) continue;
    const r = await call(u, tool, {});
    check(S, `${u.role} calling hidden ${tool} is refused`, !r.ok, short(r.error, 100));
  }
}

async function s2Auth() {
  console.log('\n[2] Auth layer (real src/auth.ts, fake Clerk)');
  const S = '2 Auth';
  const r0 = await rpc(null, 'tools/list');
  check(S, 'no token -> 401 + resource_metadata', r0.status === 401 && /resource_metadata="http:\/\/e2e\.local\/\.well-known\/oauth-protected-resource"/.test(r0.headers.get('www-authenticate') ?? ''), `HTTP ${r0.status}; ${r0.headers.get('www-authenticate')}`);
  const cases: [string, Promise<string> | string, number][] = [
    ['garbage token -> 401', 'not.a.jwt', 401],
    ['wrong issuer -> 401', mintToken(dev.sub, { iss: 'https://evil.example' }), 401],
    ['missing aud -> 401', mintToken(dev.sub, { aud: null }), 401],
    ['wrong aud -> 401', mintToken(dev.sub, { aud: 'https://other.example/mcp' }), 401],
    ['expired token -> 401', mintToken(dev.sub, { expSecs: -120 }), 401],
    ['no client_id/scope (session-token shape) -> 401', mintToken(dev.sub, { clientId: null, scope: null }), 401],
    ['HS256-signed token -> 401', mintToken(dev.sub, { hs256: true }), 401],
    ['token for a sub Clerk does not know -> 401', mintToken('user_e2e_ghost'), 401],
  ];
  clerkUsers.set('user_e2e_unknown_email', { email: 'nobody+e2e@example.invalid', verified: true });
  clerkUsers.set('user_e2e_unverified', { email: dev.email, verified: false });
  cases.push(['unknown email -> 403', mintToken('user_e2e_unknown_email'), 403]);
  cases.push(['unverified email -> 403', mintToken('user_e2e_unverified'), 403]);
  for (const [name, tok, want] of cases) {
    const r = await rpc(await tok, 'tools/list');
    const www = r.headers.get('www-authenticate') ?? '';
    check(S, name, r.status === want && (want !== 401 || www.includes('resource_metadata=')), `HTTP ${r.status} ${short(JSON.stringify(r.body), 90)}`);
  }
  const prm = await worker.fetch(new Request(`${ORIGIN}/.well-known/oauth-protected-resource`), env);
  const pj: any = await prm.json();
  check(S, 'protected-resource metadata', prm.status === 200 && pj.resource === RESOURCE && pj.authorization_servers?.[0] === FAKE_ISSUER, JSON.stringify(pj));
  const asm = await worker.fetch(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`), env);
  const aj: any = await asm.json();
  check(S, 'authorization-server metadata relayed unchanged', asm.status === 200 && aj.issuer === FAKE_ISSUER && aj.token_endpoint === `${FAKE_ISSUER}/oauth/token`, short(JSON.stringify(aj)));
}

async function s3Reads() {
  console.log('\n[3] RLS by role (reads)');
  const S = '3 RLS reads';
  const pa = await call(admin, 'get_payments', { limit: 500 });
  const pp = pm ? await call(pm, 'get_payments', { limit: 500 }) : { ok: false, error: 'no pm' };
  const [devPay] = await readAs(dev.id, (s) => s`SELECT count(*)::int AS n FROM payments WHERE archived_at IS NULL`);
  const na = pa.data?.length ?? -1, np = pp.data?.length ?? -1;
  check(S, 'get_payments: pm sees fewer than admin (and > 0)', pa.ok && pp.ok && np > 0 && np < na, `admin=${na} pm=${np}`);
  check(S, 'payments visible to developer (direct RLS count) = 0', devPay.n === 0, `developer=${devPay.n}`);
  const lt = await call(dev, 'list_tasks', { limit: 500 });
  const [expect] = await readAs(SERVICE_UID, (s) => s`SELECT count(*)::int AS n FROM tasks t
    WHERE t.archived_at IS NULL AND t.is_management = false
      AND EXISTS (SELECT 1 FROM task_assignees ta WHERE ta.task_id = t.id AND ta.user_id = ${dev.id}::uuid)`);
  const allMine = lt.ok && lt.data.every((t: any) => t.assignees.some((a: any) => a.user_id === dev.id));
  check(S, 'developer list_tasks = exactly their assigned tasks', lt.ok && lt.data.length === expect.n && allMine, `returned=${lt.data?.length} assigned=${expect.n} allAssignedToDev=${allMine}`);
  const fd = await call(dev, 'find_project', { query: '%', limit: 100 });
  const fp = pm ? await call(pm, 'find_project', { query: '%', limit: 100 }) : { ok: false, data: [] };
  const member = await readAs<{ project_id: string }>(SERVICE_UID, (s) => s`SELECT project_id FROM project_members WHERE user_id = ${dev.id}::uuid`);
  const memberSet = new Set(member.map((m) => m.project_id));
  const devOnlyMember = fd.ok && fd.data.every((p: any) => memberSet.has(p.id));
  check(S, 'find_project: developer sees only member projects', devOnlyMember, `developer=${fd.data?.length} (member of ${memberSet.size})`);
  check(S, 'find_project: pm sees more than developer', fp.ok && fp.data.length > (fd.data?.length ?? 0), `pm=${fp.data?.length} (capped at 100) developer=${fd.data?.length}`);
}

function notService(v: unknown) { return typeof v === 'string' && !SERVICE_IDS.includes(v); }

async function s5AdminWrites() {
  console.log('\n[5] Full write path as admin');
  const S = '5 Admin writes';
  const pl = await call(admin, 'list_pipelines');
  const byPipe = new Map<string, any[]>();
  for (const r of pl.data ?? []) if (r.stage_id) { if (!byPipe.has(r.pipeline_id)) byPipe.set(r.pipeline_id, []); byPipe.get(r.pipeline_id)!.push(r); }
  const [pipelineId, stages] = [...byPipe.entries()].find(([, s]) => s.length >= 2) ?? [];
  if (!pipelineId) { check(S, 'a pipeline with >= 2 stages exists', false); return; }
  ids.pipeline = pipelineId; ids.stage1 = stages![0].stage_id; ids.stage2 = stages![1].stage_id;

  const co = await call(admin, 'create_company', { name: `${PREFIX} Company (admin)`, type: 'prospect', website: 'skip', industry: 'skip', company_size: 'skip', location: 'skip', account_owner_id: 'skip' });
  check(S, 'create_company', co.ok, co.ok ? co.data.display_id : short(co.error));
  if (!co.ok) return; ids.company = co.data.id; created('company', co.data.id, admin);
  check(S, 'company created_by = acting admin', co.data.created_by === admin.id && notService(co.data.created_by), String(co.data.created_by));

  const ct = await call(admin, 'create_contact', { full_name: `${PREFIX} Contact (admin)`, status: 'prospect', primary_owner_id: 'skip', company_id: ids.company });
  check(S, 'create_contact', ct.ok, ct.ok ? ct.data.display_id : short(ct.error));
  if (!ct.ok) return; ids.contact = ct.data.id; created('contact', ct.data.id, admin);
  check(S, 'contact created_by = acting admin', ct.data.created_by === admin.id && notService(ct.data.created_by), String(ct.data.created_by));
  check(S, 'contact owner (skipped) = acting admin, not service account', ct.data.primary_owner_id === admin.id && notService(ct.data.primary_owner_id), String(ct.data.primary_owner_id));

  const dl = await call(admin, 'create_deal', { name: `${PREFIX} Deal (admin)`, contact_id: ids.contact, pipeline_id: ids.pipeline, stage_id: ids.stage1, deal_value: 1000, currency: 'USD', initial_deal_amount: 'skip', lead_type: 'skip', source: 'skip', primary_owner_id: 'skip', close_date: 'skip' });
  check(S, 'create_deal', dl.ok, dl.ok ? dl.data.display_id : short(dl.error));
  if (!dl.ok) return; ids.deal = dl.data.id; created('deal', dl.data.id, admin);
  check(S, 'deal created_by = acting admin', dl.data.created_by === admin.id && notService(dl.data.created_by), String(dl.data.created_by));
  check(S, 'deal owner (skipped) = acting admin', dl.data.primary_owner_id === admin.id, String(dl.data.primary_owner_id));
  const st = await call(admin, 'set_deal_stage', { deal_id: ids.deal, stage_id: ids.stage2 });
  check(S, 'set_deal_stage to 2nd stage', st.ok && st.data.stage_id === ids.stage2, st.ok ? '' : short(st.error));

  const pr = await call(admin, 'create_project', { name: `${PREFIX} Project`, deal_id: ids.deal, contact_id: 'skip', status: 'skip', estimated_hours: 'skip', start_date: 'skip', estimated_completion_date: 'skip', project_manager_id: pm?.id, apps: [] });
  check(S, 'create_project (pm as project manager)', pr.ok, pr.ok ? pr.data.display_id : short(pr.error));
  if (!pr.ok) return; ids.project = pr.data.id; created('project', pr.data.id, admin);
  check(S, 'project created_by = acting admin', pr.data.created_by === admin.id && notService(pr.data.created_by), String(pr.data.created_by));
  if (pm) {
    const pmm = await call(admin, 'add_project_member', { project_id: ids.project, user_id: pm.id, role: 'pm' });
    check(S, 'add_project_member (pm)', pmm.ok, pmm.ok ? '' : short(pmm.error));
    if (pmm.ok) { manifest.joins.push({ kind: 'project_member', a: ids.project, b: pm.id }); saveManifest(); }
  }

  const dm = await call(admin, 'add_project_member', { project_id: ids.project, user_id: dev.id, role: 'developer' });
  check(S, 'add_project_member (developer, for the M5 money checks)', dm.ok, dm.ok ? '' : short(dm.error));
  if (dm.ok) { manifest.joins.push({ kind: 'project_member', a: ids.project, b: dev.id }); saveManifest(); }

  const ms = await call(admin, 'create_milestone', { name: `${PREFIX} Milestone`, project_id: ids.project, status: 'skip', estimated_hours: 'skip', price: 500, currency: 'USD' });
  check(S, 'create_milestone', ms.ok, ms.ok ? ms.data.display_id : short(ms.error));
  if (!ms.ok) return; ids.milestone = ms.data.id; created('milestone', ms.data.id, admin);
  check(S, 'milestone created_by = acting admin', ms.data.created_by === admin.id && notService(ms.data.created_by), String(ms.data.created_by));

  const base = { parent_id: ids.milestone, parent_type: 'milestone', status: 'skip', priority: 'skip', plan_due_date: 'skip', estimated_hours: 'skip', requirement: 'skip', start_date: 'skip' };
  const ta = await call(admin, 'create_task', { ...base, title: `${PREFIX} Task A (developer)`, manager_ids: [dev.id], assignee_ids: 'skip' });
  check(S, 'create_task A (manager = developer only)', ta.ok, ta.ok ? ta.data.display_id : short(ta.error));
  if (ta.ok) {
    ids.taskA = ta.data.id; created('task', ta.data.id, admin);
    manifest.joins.push({ kind: 'task_manager', a: ids.taskA, b: dev.id }); saveManifest();
    check(S, 'task A created_by = acting admin, not service account', ta.data.created_by === admin.id && notService(ta.data.created_by), String(ta.data.created_by));
    const ad = await call(admin, 'add_task_assignee', { task_id: ids.taskA, user_id: dev.id });
    check(S, 'add_task_assignee (developer) on task A', ad.ok, ad.ok ? '' : short(ad.error));
    if (ad.ok) { manifest.joins.push({ kind: 'task_assignee', a: ids.taskA, b: dev.id }); saveManifest(); }
  }
  const tb = await call(admin, 'create_task', { ...base, title: `${PREFIX} Task B (unassigned)`, manager_ids: 'skip', assignee_ids: 'skip' });
  check(S, 'create_task B (no assignee, no manager)', tb.ok, tb.ok ? tb.data.display_id : short(tb.error));
  if (tb.ok) { ids.taskB = tb.data.id; created('task', tb.data.id, admin); }

  if (ids.taskA) {
    const cm = await call(admin, 'add_task_comment', { task_id: ids.taskA, body: `${PREFIX} comment from the e2e test` });
    check(S, 'add_task_comment on task A', cm.ok, cm.ok ? '' : short(cm.error));
    if (cm.ok) {
      manifest.leftovers.push({ kind: 'conversation_entry (comment)', id: cm.data.id }); saveManifest();
      const disc = await call(admin, 'get_task_discussion', { task_id: ids.taskA });
      const mine = disc.data?.comments?.find((c: any) => c.id === cm.data.id);
      check(S, 'comment sender = acting admin, not service account', mine?.sender_user_id === admin.id && mine?.posted_via_mcp === true, `sender=${mine?.sender_user_id} via_mcp=${mine?.posted_via_mcp}`);
    }
  }

  const devs = otherDev ? [{ user_id: dev.id, percent_share: 60 }, { user_id: otherDev.id, percent_share: 40 }] : [{ user_id: dev.id, percent_share: 100 }];
  const bad = await call(admin, 'create_payment', { deal_id: ids.deal, amount: 100, currency: 'USD', submitted_amount: 100, note: `${PREFIX} bad shares`, developers: [{ user_id: dev.id, percent_share: 60 }, ...(otherDev ? [{ user_id: otherDev.id, percent_share: 30 }] : [])] });
  check(S, 'create_payment with shares != 100 is refused', !bad.ok, short(bad.error, 90));
  const py = await call(admin, 'create_payment', { deal_id: ids.deal, project_id: ids.project, milestone_id: ids.milestone, amount: 100, currency: 'USD', submitted_amount: 100, note: `${PREFIX} payment`, developers: devs });
  check(S, `create_payment (developer shares ${devs.map((d) => d.percent_share).join('/')})`, py.ok, py.ok ? py.data.display_id : short(py.error));
  if (py.ok) {
    ids.payment = py.data.id; created('payment', py.data.id, admin);
    manifest.leftovers.push({ kind: 'payment_developers rows', id: ids.payment }); saveManifest();
    check(S, 'payment created_by = acting admin, not service account', py.data.created_by === admin.id && notService(py.data.created_by), String(py.data.created_by));
    const rx0 = await call(admin, 'set_payment_status', { payment_id: ids.payment, status: 'received' });
    check(S, 'set_payment_status received without INR amount is refused', !rx0.ok, short(rx0.error, 90));
    const up = await call(admin, 'update_payment', { payment_id: ids.payment, received_amount_inr: 8300 });
    check(S, 'update_payment received_amount_inr', up.ok, up.ok ? '' : short(up.error));
    const rx = await call(admin, 'set_payment_status', { payment_id: ids.payment, status: 'received' });
    check(S, 'set_payment_status received', rx.ok && rx.data.status === 'received', rx.ok ? '' : short(rx.error));
  }

  if (ids.taskB) {
    const s1 = await call(admin, 'set_task_status', { task_id: ids.taskB, status: 'in_progress' });
    check(S, 'set_task_status (admin, task B) in_progress', s1.ok && s1.data.status === 'in_progress', s1.ok ? '' : short(s1.error));
  }
  const oh0 = await call(admin, 'set_project_status', { project_id: ids.project, status: 'on_hold' });
  check(S, 'set_project_status on_hold without reason is refused', !oh0.ok, short(oh0.error, 90));
  const oh = await call(admin, 'set_project_status', { project_id: ids.project, status: 'on_hold', on_hold_reason: `${PREFIX} pause` });
  check(S, 'set_project_status on_hold with reason', oh.ok && oh.data.status === 'on_hold', oh.ok ? '' : short(oh.error));
  const back = await call(admin, 'set_project_status', { project_id: ids.project, status: 'in_progress' });
  check(S, 'set_project_status back to in_progress (reason cleared)', back.ok && back.data.on_hold_reason === null, back.ok ? '' : short(back.error));
}

async function s6OtherRoles() {
  console.log('\n[6] Write path as sales / pm / developer');
  const S = '6 Role writes';
  if (sales) {
    const co = await call(sales, 'create_company', { name: `${PREFIX} Company (sales)`, type: 'prospect', website: 'skip', industry: 'skip', company_size: 'skip', location: 'skip', account_owner_id: 'skip' });
    check(S, 'sales: create_company', co.ok, co.ok ? co.data.display_id : short(co.error));
    if (co.ok) {
      created('company', co.data.id, sales); ids.salesCompany = co.data.id;
      check(S, 'sales: company created_by = sales user', co.data.created_by === sales.id, String(co.data.created_by));
      const ct = await call(sales, 'create_contact', { full_name: `${PREFIX} Contact (sales)`, status: 'prospect', primary_owner_id: 'skip', company_id: co.data.id });
      check(S, 'sales: create_contact (owner = sales user)', ct.ok && ct.data.primary_owner_id === sales.id, ct.ok ? String(ct.data.primary_owner_id) : short(ct.error));
      if (ct.ok) {
        created('contact', ct.data.id, sales);
        check(S, 'sales: contact created_by = sales user', ct.data.created_by === sales.id, String(ct.data.created_by));
        const dl = await call(sales, 'create_deal', { name: `${PREFIX} Deal (sales)`, contact_id: ct.data.id, pipeline_id: ids.pipeline, stage_id: ids.stage1, deal_value: 500, currency: 'USD', initial_deal_amount: 'skip', lead_type: 'skip', source: 'skip', primary_owner_id: 'skip', close_date: 'skip' });
        check(S, 'sales: create_deal (owner = sales user)', dl.ok && dl.data.primary_owner_id === sales.id, dl.ok ? String(dl.data.primary_owner_id) : short(dl.error));
        if (dl.ok) { created('deal', dl.data.id, sales); ids.salesDeal = dl.data.id; ids.salesContact = ct.data.id; check(S, 'sales: deal created_by = sales user', dl.data.created_by === sales.id, String(dl.data.created_by)); }
      }
    }
  } else skip(S, 'sales writes', 'no active sales user');

  if (pm && ids.milestone) {
    const t = await call(pm, 'create_task', { title: `${PREFIX} Task (pm)`, parent_id: ids.milestone, parent_type: 'milestone', manager_ids: [dev.id], assignee_ids: [dev.id], status: 'skip', priority: 'skip', plan_due_date: 'skip', estimated_hours: 'skip', requirement: 'skip', start_date: 'skip' });
    check(S, 'pm: create_task in the test project they manage', t.ok, t.ok ? t.data.display_id : short(t.error));
    if (t.ok) {
      created('task', t.data.id, pm); ids.pmTask = t.data.id;
      manifest.joins.push({ kind: 'task_manager', a: t.data.id, b: dev.id }, { kind: 'task_assignee', a: t.data.id, b: dev.id }); saveManifest();
      check(S, 'pm task created_by = pm', t.data.created_by === pm.id, String(t.data.created_by));
    }
  } else skip(S, 'pm create_task', pm ? 'no test milestone (admin path failed)' : 'no active pm user');
}

async function s4DeveloperRules() {
  console.log('\n[4] Developer rules (test tasks only)');
  const S = '4 Developer rules';
  if (!ids.taskA || !ids.taskB) { skip(S, 'developer rules', 'test tasks were not created'); return; }
  const newTitle = `${PREFIX} Task A (developer, renamed)`;
  const f1 = await call(dev, 'update_task', { task_id: ids.taskA, title: newTitle, priority: 'high', requirement: `${PREFIX} requirement` });
  check(S, 'D2 update_task title + priority + requirement on assigned task works', f1.ok, f1.ok ? '' : short(f1.error, 110));
  if (f1.ok) {
    const rec = await call(admin, 'get_record', { entity: 'task', id: ids.taskA });
    check(S, 'D2 ...and the values were saved', rec.data?.title === newTitle && rec.data?.priority === 'high' && rec.data?.requirement === `${PREFIX} requirement`, `title=${rec.data?.title} priority=${rec.data?.priority}`);
  }
  const f2 = await call(dev, 'update_task', { task_id: ids.taskA, clear_fields: ['details'] });
  check(S, 'D2 update_task clearing a field on assigned task works', f2.ok, f2.ok ? '' : short(f2.error, 110));
  const f3 = await call(dev, 'update_task', { task_id: ids.taskA, is_management: true });
  check(S, 'D2/M6 developer update_task is_management refused', !f3.ok && /cannot change: is_management/.test(f3.error ?? ''), short(f3.error, 110));
  const nb = await call(dev, 'update_task', { task_id: ids.taskB, loom_url: 'https://example.com/mcp-test-b' });
  check(S, 'update_task on a task NOT assigned to the developer refused', !nb.ok && /assigned to/.test(nb.error ?? ''), short(nb.error, 90));
  const ok = await call(dev, 'update_task', { task_id: ids.taskA, loom_url: 'https://example.com/mcp-test', time_reported_hours: 1.5 });
  check(S, 'update_task loom_url + time_reported_hours on assigned task works', ok.ok, ok.ok ? '' : short(ok.error));
  if (ok.ok) {
    const rec = await call(admin, 'get_record', { entity: 'task', id: ids.taskA });
    check(S, '…and the values were saved', rec.data?.loom_url === 'https://example.com/mcp-test' && Number(rec.data?.time_reported_hours) === 1.5, `loom=${rec.data?.loom_url} hours=${rec.data?.time_reported_hours}`);
  }
  const so = await call(dev, 'set_task_status', { task_id: ids.taskA, status: 'in_progress' });
  check(S, 'set_task_status on own (assigned) task works', so.ok && so.data.status === 'in_progress', so.ok ? '' : short(so.error));
  const sq = await call(dev, 'set_task_status', { task_id: ids.taskA, status: 'qa_review' });
  check(S, 'M2 developer set_task_status qa_review works', sq.ok && sq.data.status === 'qa_review', sq.ok ? '' : short(sq.error));
  for (const st of ['done', 'stuck']) {
    const r = await call(dev, 'set_task_status', { task_id: ids.taskA, status: st });
    check(S, `M2 developer set_task_status ${st} refused`, !r.ok && /can only set these statuses/.test(r.error ?? ''), short(r.error, 100));
  }
  const sx = await call(dev, 'set_task_status', { task_id: ids.taskB, status: 'in_progress' });
  check(S, 'set_task_status on another task refused', !sx.ok, short(sx.error, 90));
  const today = new Date().toISOString().slice(0, 10);
  const week = new Date(Date.now() + 7 * 864e5).toISOString().slice(0, 10);
  const av1 = await call(dev, 'get_developer_availability', { date_from: today, date_to: week, user_id: otherDev?.id ?? admin.id });
  check(S, 'get_developer_availability for another user refused', !av1.ok && /own availability/.test(av1.error ?? ''), short(av1.error, 90));
  const av2 = await call(dev, 'get_developer_availability', { date_from: today, date_to: week });
  check(S, 'get_developer_availability without user_id returns only self', av2.ok && av2.data.length <= 1 && av2.data.every((d: any) => d.user_id === dev.id), av2.ok ? `entries=${av2.data.length}` : short(av2.error));
  const lt = await call(dev, 'list_tasks', { search: PREFIX, limit: 50 });
  const titles = (lt.data ?? []).map((t: any) => t.title);
  check(S, 'developer list_tasks shows test task A but not B', lt.ok && titles.some((t: string) => t.includes('Task A')) && !titles.some((t: string) => t.includes('Task B')), `seen=${JSON.stringify(titles)}`);
}

// A valid 1x1 PNG (68 bytes) — ends with the IEND chunk.
const PNG = Uint8Array.from(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64'));

async function s7Uploads() {
  console.log(`\n[7] File upload (PUT to npm run dev at ${DEV_BASE})`);
  const S = '7 Uploads';
  if (!ids.taskA) { skip(S, 'uploads', 'test task A missing'); return; }
  try { await realFetch(`${DEV_BASE}/health`); } catch { skip(S, 'uploads', `dev server not reachable at ${DEV_BASE}`); return; }
  const start = async (u: User, size: number, name: string) => call(u, 'start_attachment_upload', { parent_type: 'task', parent_id: ids.taskA, file_name: `${PREFIX} ${name}`, mime_type: 'image/png', file_size_bytes: size, purpose: 'e2e' });
  const put = (uploadUrl: string, bytes: Uint8Array) => realFetch(uploadUrl.replace(ORIGIN, DEV_BASE), { method: 'PUT', headers: { 'Content-Type': 'image/png' }, body: bytes });

  const s = await start(admin, PNG.length, 'pixel.png');
  check(S, 'start_attachment_upload (admin)', s.ok, s.ok ? '' : short(s.error));
  if (!s.ok) return;
  const r = await put(s.data.upload_url, PNG);
  const rj: any = await r.json();
  check(S, 'PUT valid PNG -> 200 ok', r.status === 200 && rj.ok === true, `HTTP ${r.status}`);
  if (r.ok) manifest.leftovers.push({ kind: 'attachment (+blob)', id: s.data.attachment_id }); saveManifest();
  const fin = await call(admin, 'finalize_attachment_upload', { attachment_id: s.data.attachment_id });
  check(S, 'finalize_attachment_upload confirms the file', fin.ok && fin.data.attached === true && fin.data.size_bytes === PNG.length, fin.ok ? `size=${fin.data.size_bytes}` : short(fin.error));
  const la = await call(admin, 'list_attachments', { parent_type: 'task', parent_id: ids.taskA });
  const att = la.data?.find((x: any) => x.id === s.data.attachment_id);
  check(S, 'attachment uploaded_by = acting admin', att?.uploaded_by_name === admin.full_name, `uploaded_by_name=${att?.uploaded_by_name}`);

  const replay = await put(s.data.upload_url, PNG);
  check(S, 'reusing the upload link -> 409', replay.status === 409, `HTTP ${replay.status}`);

  const s2 = await start(admin, PNG.length, 'tampered.png');
  if (s2.ok) {
    const u = s2.data.upload_url as string;
    const tampered = u.slice(0, -2) + (u.endsWith('AA') ? 'BB' : 'AA');
    const t = await put(tampered, PNG);
    check(S, 'tampered token -> 401', t.status === 401, `HTTP ${t.status}`);
  }
  const s3 = await start(admin, PNG.length + 5, 'mismatch.png');
  if (s3.ok) {
    const m = await put(s3.data.upload_url, PNG);
    check(S, 'size mismatch -> 400, nothing stored', m.status === 400, `HTTP ${m.status}`);
  }
  const cut = PNG.slice(0, PNG.length - 12);
  const s4 = await start(admin, cut.length, 'truncated.png');
  if (s4.ok) {
    const tr = await put(s4.data.upload_url, cut);
    const tj: any = await tr.json();
    check(S, 'truncated PNG -> 422, nothing stored', tr.status === 422, `HTTP ${tr.status} ${short(tj.error, 80)}`);
    const f4 = await call(admin, 'finalize_attachment_upload', { attachment_id: s4.data.attachment_id });
    check(S, 'finalize on the refused upload reports failure', !f4.ok, short(f4.error, 80));
  }
  // Developer uploading to their own assigned task.
  const sd = await start(dev, PNG.length, 'dev-pixel.png');
  if (sd.ok) {
    const pd = await put(sd.data.upload_url, PNG);
    if (pd.ok) manifest.leftovers.push({ kind: 'attachment (+blob)', id: sd.data.attachment_id }); saveManifest();
    const fd = await call(dev, 'finalize_attachment_upload', { attachment_id: sd.data.attachment_id });
    check(S, 'developer: upload to own assigned task works', pd.status === 200 && fd.ok, `PUT ${pd.status}, finalize ${fd.ok ? 'ok' : short(fd.error, 60)}`);
  } else check(S, 'developer: start_attachment_upload on own task', false, short(sd.error, 100));
}

async function s9Portal() {
  console.log('\n[9] Portal role rules (M1-M6, D1-D6, EXTRA, ratings)');
  const S = '9 Portal rules';
  if (!ids.milestone || !ids.taskA || !ids.taskB) { skip(S, 'portal rules', 'test records missing'); return; }
  const base = { parent_id: ids.milestone, parent_type: 'milestone', priority: 'skip', plan_due_date: 'skip', estimated_hours: 'skip', requirement: 'skip', start_date: 'skip' };
  const other = otherDev?.id ?? admin.id;

  // D1 + M2 + M6 — developer create_task
  const d1 = await call(dev, 'create_task', { ...base, title: `${PREFIX} Task (developer self)`, status: 'skip', manager_ids: [dev.id], assignee_ids: [dev.id] });
  check(S, 'D1 developer create_task assigned to self works', d1.ok, d1.ok ? d1.data.display_id : short(d1.error));
  if (d1.ok) {
    created('task', d1.data.id, dev); ids.devTask = d1.data.id;
    manifest.joins.push({ kind: 'task_manager', a: d1.data.id, b: dev.id }, { kind: 'task_assignee', a: d1.data.id, b: dev.id }); saveManifest();
    check(S, 'D1 ...created_by = developer, is_management false', d1.data.created_by === dev.id && d1.data.is_management === false, `${d1.data.created_by} mgmt=${d1.data.is_management}`);
  }
  for (const [label, assignees] of [['another user', [other]], ['"skip" (unassigned)', 'skip'], ['self + another user', [dev.id, other]]] as const) {
    const r = await call(dev, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'skip', manager_ids: 'skip', assignee_ids: assignees });
    check(S, `D1 developer create_task assigned to ${label} refused`, !r.ok && /assigned to yourself/.test(r.error ?? ''), short(r.error, 100));
  }
  const d2 = await call(dev, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'done', manager_ids: 'skip', assignee_ids: [dev.id] });
  check(S, 'M2 developer create_task status=done refused', !d2.ok && /can only set these statuses/.test(d2.error ?? ''), short(d2.error, 100));
  const d3 = await call(dev, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'skip', manager_ids: 'skip', assignee_ids: [dev.id], is_management: true });
  check(S, 'M6 developer create_task is_management=true refused', !d3.ok && /management task/.test(d3.error ?? ''), short(d3.error, 100));

  // D6 — operations: same tools and rules as developer
  if (ops) {
    const o1 = await call(ops, 'create_task', { ...base, title: `${PREFIX} Task (operations self)`, status: 'skip', manager_ids: 'skip', assignee_ids: [ops.id] });
    check(S, 'D6/D1 operations create_task assigned to self works', o1.ok, o1.ok ? o1.data.display_id : short(o1.error));
    if (o1.ok) {
      created('task', o1.data.id, ops); ids.opsTask = o1.data.id;
      manifest.joins.push({ kind: 'task_assignee', a: o1.data.id, b: ops.id }); saveManifest();
      check(S, 'D6 ...created_by = operations user', o1.data.created_by === ops.id, String(o1.data.created_by));
      const ou = await call(ops, 'update_task', { task_id: o1.data.id, title: `${PREFIX} Task (operations, renamed)`, priority: 'low' });
      check(S, 'D6/D2 operations update_task on own task works', ou.ok && ou.data.task?.priority === 'low', ou.ok ? '' : short(ou.error));
      const oq = await call(ops, 'set_task_status', { task_id: o1.data.id, status: 'qa_review' });
      check(S, 'D6/M2 operations set_task_status qa_review works', oq.ok && oq.data.status === 'qa_review', oq.ok ? '' : short(oq.error));
      const od = await call(ops, 'set_task_status', { task_id: o1.data.id, status: 'done' });
      check(S, 'D6/M2 operations set_task_status done refused', !od.ok && /can only set these statuses/.test(od.error ?? ''), short(od.error, 100));
    }
    const o2 = await call(ops, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'skip', manager_ids: 'skip', assignee_ids: [dev.id] });
    check(S, 'D6/D1 operations create_task assigned to someone else refused', !o2.ok && /assigned to yourself/.test(o2.error ?? ''), short(o2.error, 100));
    const o3 = await call(ops, 'update_task', { task_id: ids.taskB, title: `${PREFIX} nope` });
    check(S, 'D6/D2 operations update_task on a task not assigned to them refused', !o3.ok, short(o3.error, 100));
  } else skip(S, 'operations rules', 'no active operations user');

  // M6 — is_management
  const m1 = await call(admin, 'create_task', { ...base, title: `${PREFIX} Task (management)`, status: 'skip', manager_ids: [dev.id], assignee_ids: [dev.id], is_management: true });
  check(S, 'M6 admin create_task is_management=true works', m1.ok && m1.data.is_management === true, m1.ok ? m1.data.display_id : short(m1.error));
  if (m1.ok) {
    created('task', m1.data.id, admin); ids.mgmtTask = m1.data.id;
    manifest.joins.push({ kind: 'task_manager', a: m1.data.id, b: dev.id }, { kind: 'task_assignee', a: m1.data.id, b: dev.id }); saveManifest();
    const m2 = await call(admin, 'update_task', { task_id: m1.data.id, is_management: false });
    check(S, 'M6 admin update_task is_management=false works', m2.ok && m2.data.task?.is_management === false, m2.ok ? '' : short(m2.error));
  }
  if (pm) {
    const m3 = await call(pm, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'skip', manager_ids: [dev.id], assignee_ids: 'skip', is_management: true });
    check(S, 'M6 pm create_task is_management=true refused', !m3.ok && /management task/.test(m3.error ?? ''), short(m3.error, 100));
    if (ids.pmTask) {
      const m4 = await call(pm, 'update_task', { task_id: ids.pmTask, is_management: true });
      check(S, 'M6 pm update_task is_management refused', !m4.ok && /cannot set or change is_management/.test(m4.error ?? ''), short(m4.error, 100));
    }
  }

  // M4 — payment "received"
  if (pm && ids.payment) {
    const p1 = await call(pm, 'set_payment_status', { payment_id: ids.payment, status: 'received' });
    check(S, 'M4 pm set_payment_status received refused (clear message)', !p1.ok && /Only an admin or super admin/.test(p1.error ?? ''), short(p1.error, 100));
    const p2 = await call(pm, 'create_payment', { deal_id: ids.deal, amount: 50, currency: 'USD', submitted_amount: 50, status: 'received', note: `${PREFIX} should not exist` });
    check(S, 'M4 pm create_payment status=received refused', !p2.ok && /Only an admin or super admin/.test(p2.error ?? ''), short(p2.error, 100));
  }
  if (sa && ids.deal) {
    const p3 = await call(sa, 'create_payment', { deal_id: ids.deal, amount: 50, currency: 'USD', submitted_amount: 50, received_amount_inr: 4150, status: 'received', note: `${PREFIX} payment (super_admin received)` });
    check(S, 'M4 super_admin create_payment status=received works', p3.ok && p3.data.status === 'received', p3.ok ? p3.data.display_id : short(p3.error));
    if (p3.ok) created('payment', p3.data.id, sa);
  } else skip(S, 'M4 super_admin', 'no active super_admin user');

  // M5 — money columns
  if (pm) {
    const g = await call(pm, 'get_record', { entity: 'milestone', id: ids.milestone });
    check(S, 'M5 pm get_record milestone shows price/currency', g.ok && Number(g.data?.price) === 500 && g.data?.currency?.trim() === 'USD', `price=${g.data?.price} currency=${g.data?.currency}`);
  }
  for (const u of [sales, dev, ops].filter(Boolean) as User[]) {
    const g = await call(u, 'get_record', { entity: 'milestone', id: ids.milestone });
    check(S, `M5 ${u.role} get_record milestone has no price/currency`, g.ok && g.data?.id === ids.milestone && !hasMoney(g.data), g.ok ? `keys=${Object.keys(g.data ?? {}).length}` : short(g.error));
    const fp = await call(u, 'find_project', { query: PREFIX, limit: 20 });
    check(S, `M5 ${u.role} find_project has no money fields`, fp.ok && !hasMoney(fp.data), fp.ok ? `rows=${fp.data.length}` : short(fp.error));
    if (u !== sales) {
      const fm = await call(u, 'find_milestone', { project_id: ids.project });
      check(S, `M5 ${u.role} find_milestone has no price/currency`, fm.ok && fm.data.length > 0 && !hasMoney(fm.data), fm.ok ? `rows=${fm.data.length}` : short(fm.error));
      const lt = await call(u, 'list_tasks', { search: PREFIX, full: true, limit: 50 });
      check(S, `M5 ${u.role} list_tasks has no money fields`, lt.ok && !hasMoney(lt.data), lt.ok ? `rows=${lt.data.length}` : short(lt.error));
    }
  }

  // get_record deal / payment
  for (const u of [dev, ops].filter(Boolean) as User[]) {
    const gd = await call(u, 'get_record', { entity: 'deal', id: ids.deal });
    check(S, `${u.role} get_record deal refused`, !gd.ok && /cannot fetch deal/.test(gd.error ?? ''), short(gd.error, 90));
    const gp = await call(u, 'get_record', { entity: 'payment', id: ids.payment ?? ids.deal });
    check(S, `${u.role} get_record payment refused`, !gp.ok && /cannot fetch payment/.test(gp.error ?? ''), short(gp.error, 90));
  }
  const ga = await call(admin, 'get_record', { entity: 'deal', id: ids.deal });
  check(S, 'admin get_record deal works', ga.ok && ga.data?.id === ids.deal, ga.ok ? '' : short(ga.error));
  if (sales && ids.salesDeal) {
    const gs = await call(sales, 'get_record', { entity: 'deal', id: ids.salesDeal });
    check(S, 'sales get_record deal works (deal_value kept)', gs.ok && gs.data?.id === ids.salesDeal && 'deal_value' in (gs.data ?? {}), gs.ok ? `deal_value=${gs.data?.deal_value}` : short(gs.error));
    const gp = await call(sales, 'get_record', { entity: 'payment', id: ids.payment ?? ids.deal });
    check(S, 'sales get_record payment refused', !gp.ok && /cannot fetch payment/.test(gp.error ?? ''), short(gp.error, 90));
  }

  // D4 — sales get_credentials (metadata only)
  if (sales && ids.salesContact) {
    const c = await call(sales, 'get_credentials', { parent_type: 'contact', parent_id: ids.salesContact });
    check(S, 'D4 sales get_credentials works (metadata only)', c.ok && typeof c.data?.count === 'number' && !/secret_ref|password/i.test(JSON.stringify(c.data?.credentials ?? [])), c.ok ? `count=${c.data.count}` : short(c.error));
  }

  // EXTRA — pm self-assign
  if (pm) {
    const e1 = await call(pm, 'add_task_assignee', { task_id: ids.taskB, user_id: pm.id });
    check(S, 'EXTRA pm self-assign on a task they neither manage nor created refused', !e1.ok && /manage or created/.test(e1.error ?? ''), short(e1.error, 100));
    if (ids.pmTask) {
      const e2 = await call(pm, 'add_task_assignee', { task_id: ids.pmTask, user_id: pm.id });
      check(S, 'EXTRA pm self-assign on a task they created works', e2.ok && !e2.data?.already_assigned, e2.ok ? '' : short(e2.error));
      if (e2.ok) { manifest.joins.push({ kind: 'task_assignee', a: ids.pmTask, b: pm.id }); saveManifest(); }
      const e3 = await call(pm, 'add_task_assignee', { task_id: ids.pmTask, user_id: dev.id });
      check(S, 'EXTRA pm assigning someone else is not limited', e3.ok, e3.ok ? JSON.stringify(e3.data).slice(0, 60) : short(e3.error));
    }
  }

  // D3 — sales archive: deals only
  if (sales && ids.salesCompany && ids.salesDeal) {
    const a1 = await call(sales, 'archive_record', { entity: 'company', id: ids.salesCompany, reason: CLEANUP_REASON });
    check(S, 'D3 sales archive_record company refused', !a1.ok && /cannot archive company/.test(a1.error ?? ''), short(a1.error, 100));
    const a2 = await call(sales, 'archive_record', { entity: 'deal', id: ids.salesDeal, reason: CLEANUP_REASON });
    check(S, 'D3 sales archive_record deal works', a2.ok && a2.data?.archived === 'deal', a2.ok ? '' : short(a2.error));
  }

  // M3 — done needs every assignee rated (runs last: it closes task A and task B)
  const r1 = await call(admin, 'set_task_status', { task_id: ids.taskA, status: 'done' });
  check(S, 'M3 admin done on task with an unrated assignee refused', !r1.ok && /Rate every assignee/.test(r1.error ?? '') && r1.error!.includes(dev.full_name), short(r1.error, 120));
  if (pm && ids.pmTask) {
    const r2 = await call(pm, 'set_task_status', { task_id: ids.pmTask, status: 'done' });
    check(S, 'M3 pm done on task with unrated assignees refused', !r2.ok && /Rate every assignee/.test(r2.error ?? ''), short(r2.error, 120));
  }
  const r3 = await call(admin, 'create_task', { ...base, title: `${PREFIX} should not exist`, status: 'done', manager_ids: 'skip', assignee_ids: [dev.id] });
  check(S, 'M3 admin create_task status=done with an assignee refused', !r3.ok && /cannot be created as done/.test(r3.error ?? ''), short(r3.error, 120));
  const r4 = await call(admin, 'create_task', { ...base, title: `${PREFIX} Task (created done, no assignees)`, status: 'done', manager_ids: 'skip', assignee_ids: 'skip' });
  check(S, 'M3 admin create_task status=done with no assignees works', r4.ok && r4.data.status === 'done', r4.ok ? r4.data.display_id : short(r4.error));
  if (r4.ok) created('task', r4.data.id, admin);
  const r5 = await call(admin, 'set_task_status', { task_id: ids.taskB, status: 'done' });
  check(S, 'M3 admin done on task with no assignees works', r5.ok && r5.data.status === 'done', r5.ok ? '' : short(r5.error));
  if (sa) {
    const r6 = await call(sa, 'set_task_status', { task_id: ids.taskA, status: 'done' });
    check(S, 'M3 super_admin done on task with an unrated assignee works', r6.ok && r6.data.status === 'done', r6.ok ? '' : short(r6.error));
  }
}

function sRatings() {
  console.log('\n[10] Ratings never leave the server');
  check('10 Ratings', `no tool output contains work_ratings fields (${outputsScanned} outputs scanned)`, ratingLeaks.length === 0, ratingLeaks.slice(0, 5).join(', '));
}

// ---------------------------------------------------------------------------
let failedCleanup: string[] = [];
try {
  if (!CLEANUP_ONLY) {
    if (manifest.records.length) console.log(`\nNOTE: manifest has ${manifest.records.length} record(s) from an earlier run; they will be cleaned up too.`);
    await s1Visibility();
    await s2Auth();
    await s3Reads();
    await s5AdminWrites();
    await s6OtherRoles();
    await s4DeveloperRules();
    await s7Uploads();
    await s9Portal();
    sRatings();
  }
} catch (e) {
  check('runtime', 'test run completed without crashing', false, short(e instanceof Error ? `${e.message} ${e.stack?.split('\n')[1] ?? ''}` : String(e), 300));
} finally {
  failedCleanup = await cleanup();
}

console.log('\n================ SUMMARY ================');
const by = (r: Row['result']) => results.filter((x) => x.result === r).length;
console.log(`PASS ${by('PASS')}   FAIL ${by('FAIL')}   SKIP ${by('SKIP')}`);
for (const r of results.filter((x) => x.result !== 'PASS')) console.log(`  ${r.result}  [${r.section}] ${r.check}  — ${r.detail}`);
console.log('\nLeft in the database by design (cannot be archived through MCP; all hang off archived [MCP-TEST] parents):');
for (const l of manifest.leftovers) console.log(`  ${l.kind}: ${l.id}`);
console.log('  plus: contact_owners / deal_owners rows, milestone_members (pm, via trigger), audit_log rows,');
console.log('        task_notification_outbox rows (recipient U-0068; plus U-0080 and U-0028 for the two approved self-assign cases)');
if (failedCleanup.length) console.log(`\nCOULD NOT ARCHIVE: ${failedCleanup.join(', ')}`);
writeFileSync('.wrangler/e2e-results.json', JSON.stringify({ results, leftovers: manifest.leftovers, failedCleanup }, null, 2));
process.exit(by('FAIL') > 0 ? 1 : 0);
