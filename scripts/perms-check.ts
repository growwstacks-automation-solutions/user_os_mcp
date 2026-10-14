// scripts/perms-check.ts — `npm run perms:check`
//
// Prints, for every role, the tools it would see in tools/list, by running the
// REAL registerTools (with its role gate) against a fake server that only
// records names. Registering tools makes no database or network calls, so this
// needs no secrets and touches nothing.
//
// Fails (exit 1) when:
//   * a role's allowed list names a tool that is not defined in tools.ts
//     (a typo, or a tool that was renamed/removed), or
//   * a tool defined in tools.ts is missing from ALL_TOOLS (nobody could ever
//     be offered it, not even admins), or
//   * any portal role rule below (allowed AND refused case) does not hold.

import { readFileSync } from 'node:fs';

import type { Identity } from '../src/auth';
import type { Env } from '../src/db';
import {
  ALL_TOOLS, NEVER_RETURN_FIELDS, ROLE_RULES, ROLE_TOOLS,
  archiveAllowed, can, doneRule, isToolAllowed, recordAllowed, rulesFor, statusAllowed, stripMoney, toolsForRole,
} from '../src/permissions';
import { registerTools } from '../src/tools';

// The user_role enum on the OS database (read from the Neon test branch).
const DB_ROLES = [
  'admin', 'pm', 'developer', 'sales', 'finance', 'viewer', 'super_admin', 'internal', 'operations',
];

const fakeEnv = {
  DATABASE_URL: 'postgresql://unused',
  CLERK_ISSUER: 'unused',
  CLERK_JWKS_URL: 'unused',
  CLERK_SECRET_KEY: 'unused',
  UPLOAD_SIGNING_KEY: 'unused',
} as Env;

/** The names registerTools actually registers for this role. */
function registeredFor(role: string): string[] {
  const names: string[] = [];
  const recorder = { tool: (name: string) => { names.push(name); } };
  const identity: Identity = { id: '00000000-0000-0000-0000-000000000000', role, email: 'x', name: null };
  registerTools(recorder as never, fakeEnv, 'http://localhost', identity);
  return names;
}

const problems: string[] = [];

// Every tool DEFINED in tools.ts, read from the source (independent of the gate).
const source = readFileSync('src/tools.ts', 'utf8');
const defined = [...source.matchAll(/server\.tool\(\s*'([a-z_]+)'/g)].map((m) => m[1]);
for (const name of defined) {
  if (!(ALL_TOOLS as readonly string[]).includes(name)) {
    problems.push(`tool "${name}" is defined in tools.ts but missing from ALL_TOOLS`);
  }
}

const roles = [...new Set([...DB_ROLES, ...Object.keys(ROLE_TOOLS)])];
for (const role of roles.filter((r) => !DB_ROLES.includes(r))) {
  problems.push(`role "${role}" is in ROLE_TOOLS but not in the database's user_role enum`);
}

console.log(`Tools defined in src/tools.ts: ${defined.length}   ALL_TOOLS: ${ALL_TOOLS.length}\n`);
for (const role of roles) {
  const allowed = toolsForRole(role);
  const seen = registeredFor(role);
  for (const name of allowed) {
    if (!seen.includes(name)) problems.push(`role "${role}" allows "${name}", but no such tool is registered`);
  }
  const rules = Object.hasOwn(ROLE_RULES, role) ? Object.keys(ROLE_RULES[role]) : [];
  console.log(`${role.padEnd(12)} ${String(seen.length).padStart(2)} tools${seen.length === 0 ? '  (no MCP access: sign-in refused with 403)' : ''}`);
  if (seen.length > 0 && seen.length < ALL_TOOLS.length) console.log(`             ${seen.join(', ')}`);
  if (seen.length === ALL_TOOLS.length) console.log('             (all tools)');
  if (rules.length > 0) console.log(`             limits inside: ${rules.join(', ')}`);
}

// ---------------------------------------------------------------------------
// Portal role rules: every rule, an allowed and a refused case.
// ---------------------------------------------------------------------------
const ruleChecks: [string, boolean][] = [];
const rule = (name: string, ok: boolean) => ruleChecks.push([name, ok]);
const same = (a: readonly string[], b: readonly string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);
const DELIVERY = ['developer', 'operations'];

// Tool counts
const COUNTS: Record<string, number> = { super_admin: 48, admin: 48, pm: 48, sales: 24, developer: 18, operations: 18, internal: 0, finance: 0, viewer: 0 };
for (const [r, n] of Object.entries(COUNTS)) rule(`${r} has ${n} tools`, registeredFor(r).length === n);
// M1
rule('M1 internal: no access', toolsForRole('internal').length === 0);
// D6
rule('D6 operations tools = developer tools', same(toolsForRole('operations'), toolsForRole('developer')));
rule('D6 operations rules = developer rules', JSON.stringify(ROLE_RULES.operations) === JSON.stringify(ROLE_RULES.developer));
// M2
for (const r of DELIVERY) {
  for (const st of ['todo', 'in_progress', 'qa_review']) rule(`M2 ${r} may set ${st}`, statusAllowed(r, st));
  for (const st of ['done', 'stuck', 'client_review']) rule(`M2 ${r} refused ${st}`, !statusAllowed(r, st));
}
rule('M2 admin may set any status', statusAllowed('admin', 'stuck') && statusAllowed('admin', 'done'));
// M3
rule('M3 super_admin marks done always', doneRule('super_admin') === 'always');
rule('M3 admin needs ratings', doneRule('admin') === 'if_all_assignees_rated');
rule('M3 pm needs ratings', doneRule('pm') === 'if_all_assignees_rated');
for (const r of [...DELIVERY, 'sales', 'internal']) rule(`M3 ${r} never marks done`, doneRule(r) === 'never');
// M4
for (const r of ['super_admin', 'admin']) rule(`M4 ${r} may mark received`, can(r, 'markPaymentReceived'));
for (const r of ['pm', 'sales', ...DELIVERY]) rule(`M4 ${r} refused received`, !can(r, 'markPaymentReceived'));
// M5
const ms = { id: 'x', name: 'm', price: 10, currency: 'USD' };
for (const r of ['super_admin', 'admin', 'pm']) rule(`M5 ${r} sees milestone price/currency`, 'price' in stripMoney(r, 'milestone', ms) && 'currency' in stripMoney(r, 'milestone', ms));
for (const r of ['sales', ...DELIVERY]) {
  const out = stripMoney(r, 'milestone', ms);
  rule(`M5 ${r}: milestone price/currency stripped, rest kept`, !('price' in out) && !('currency' in out) && out.name === 'm');
}
// M6
for (const r of ['super_admin', 'admin']) rule(`M6 ${r} may set is_management`, can(r, 'setManagementTask'));
for (const r of ['pm', ...DELIVERY]) rule(`M6 ${r} refused is_management`, !can(r, 'setManagementTask'));
// D1
for (const r of DELIVERY) rule(`D1 ${r} create_task is self-assign only`, isToolAllowed(r, 'create_task') && rulesFor(r, 'create_task')?.selfAssignOnly === true);
rule('D1 pm create_task not self-assign limited', rulesFor('pm', 'create_task') === undefined);
// D2
for (const r of DELIVERY) {
  const u = rulesFor(r, 'update_task');
  rule(`D2 ${r} update_task assignee-only`, u?.assigneeOnly === true);
  rule(`D2 ${r} cannot move a task or flag management`, ['parent_type', 'parent_id', 'project_id', 'milestone_id', 'is_management'].every((f) => u?.deniedFields.includes(f)));
  rule(`D2 ${r} may change title/priority/requirement/details`, ['title', 'priority', 'requirement', 'details', 'loom_url'].every((f) => !u?.deniedFields.includes(f)));
}
// D3
rule('D3 sales may archive deals', isToolAllowed('sales', 'archive_record') && archiveAllowed('sales', 'deal'));
for (const e of ['company', 'contact', 'project', 'task', 'payment'] as const) rule(`D3 sales refused archive ${e}`, !archiveAllowed('sales', e));
rule('D3 admin may archive anything', archiveAllowed('admin', 'company'));
// D4
rule('D4 sales has get_credentials', isToolAllowed('sales', 'get_credentials'));
// get_record deal/payment
for (const r of DELIVERY) {
  rule(`get_record: ${r} refused deal`, !recordAllowed(r, 'deal'));
  rule(`get_record: ${r} refused payment`, !recordAllowed(r, 'payment'));
  rule(`get_record: ${r} may fetch task/milestone`, recordAllowed(r, 'task') && recordAllowed(r, 'milestone'));
}
rule('get_record: sales may fetch deal, refused payment', recordAllowed('sales', 'deal') && !recordAllowed('sales', 'payment'));
rule('get_record: pm may fetch deal and payment', recordAllowed('pm', 'deal') && recordAllowed('pm', 'payment'));
// EXTRA
rule('EXTRA pm self-assign needs manager/creator', rulesFor('pm', 'add_task_assignee')?.selfNeedsManagerOrCreator === true);
rule('EXTRA admin self-assign unrestricted', rulesFor('admin', 'add_task_assignee') === undefined);
// RATINGS
for (const f of ['timely_delivery', 'quality', 'rater_user_id', 'ratee_user_id', 'stars', 'avg_rating']) rule(`RATINGS ${f} is never returned`, NEVER_RETURN_FIELDS.has(f));

const bad = ruleChecks.filter(([, ok]) => !ok);
console.log(`
Portal role rules: ${ruleChecks.length - bad.length}/${ruleChecks.length} hold`);
for (const [name] of bad) problems.push(`rule failed: ${name}`);

if (problems.length > 0) {
  console.error(`\nFAILED — ${problems.length} problem(s):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('\nOK — every allowed name matches a registered tool.');
