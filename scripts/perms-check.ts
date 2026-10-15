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
//   * any portal role rule below (allowed AND refused case) does not hold, or
//   * a ROLE_RULES limit has no matching sentence in that role's tool
//     description (or a description carries a sentence no rule explains).

import { readFileSync } from 'node:fs';

import type { Identity } from '../src/auth';
import type { Env } from '../src/db';
import {
  ALL_TOOLS, NEVER_RETURN_FIELDS, ROLE_RULES, ROLE_TOOLS,
  archiveAllowed, can, doneRule, isToolAllowed, limitSentences, recordAllowed, rulesFor, statusAllowed, stripMoney, toolsForRole,
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

/** What registerTools actually registers for this role: name -> description. */
function registeredWithDescriptions(role: string): Map<string, string> {
  const tools = new Map<string, string>();
  const recorder = { tool: (name: string, description: string) => { tools.set(name, description); } };
  const identity: Identity = { id: '00000000-0000-0000-0000-000000000000', role, email: 'x', name: null };
  registerTools(recorder as never, fakeEnv, 'http://localhost', identity);
  return tools;
}
const registeredFor = (role: string): string[] => [...registeredWithDescriptions(role).keys()];

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

// ---------------------------------------------------------------------------
// Role-aware descriptions: every ROLE_RULES limit must show up as a sentence
// on each affected tool the role has, and no other sentence may appear.
// The expectations below are written from the rule KEYS, independently of
// limitSentences, so a rule added without a sentence fails here.
// ---------------------------------------------------------------------------
const KNOWN_KEYS = new Set(['taskStatuses', 'markTaskDone', 'setManagementTask', 'markPaymentReceived', 'seeMoney',
  'create_task', 'update_task', 'set_task_status', 'get_developer_availability', 'get_record', 'archive_record', 'add_task_assignee']);
const base = registeredWithDescriptions('super_admin');
console.log('\nRole limit sentences in tool descriptions:');
for (const r of roles) {
  const rr = Object.hasOwn(ROLE_RULES, r) ? ROLE_RULES[r] : {};
  for (const k of Object.keys(rr)) if (!KNOWN_KEYS.has(k)) problems.push(`ROLE_RULES.${r}.${k} has no description sentence mapping`);
  const exp: [string, RegExp][] = [];
  const want = (tools: string[], re: RegExp) => { for (const t of tools) exp.push([t, re]); };
  if (rr.create_task?.selfAssignOnly) want(['create_task'], /You can only create tasks assigned to yourself\./);
  if (!rr.setManagementTask) want(['create_task', 'update_task'], /You cannot create or change management tasks\./);
  if (rr.taskStatuses) want(['set_task_status', 'create_task'], new RegExp(`You can only set: ${rr.taskStatuses.join(', ')}\\.`));
  if (statusAllowed(r, 'done') && rr.markTaskDone === 'if_all_assignees_rated') want(['set_task_status', 'create_task'], /Done only when every assignee has been rated\./);
  if (statusAllowed(r, 'done') && !rr.markTaskDone) want(['set_task_status', 'create_task'], /You cannot mark a task done\./);
  if (rr.set_task_status?.assigneeOnly) want(['set_task_status'], /Only tasks you are assigned to\./);
  if (rr.update_task) {
    const other = rr.update_task.deniedFields.filter((f) => !/parent_|project_id|milestone_id/.test(f) && !(f === 'is_management' && !rr.setManagementTask));
    want(['update_task'], new RegExp(`Only tasks you are assigned to; you cannot move a task${other.length ? ` or change: ${other.join(', ')}` : ''}\\.`));
  }
  if (rr.get_developer_availability?.selfOnly) want(['get_developer_availability'], /Only your own availability\./);
  if (rr.get_record) want(['get_record'], new RegExp(`You cannot fetch ${rr.get_record.deniedEntities.map((e) => `${e}s`).join(' or ')}\\.`));
  if (rr.archive_record) want(['archive_record'], new RegExp(`You can only archive: ${rr.archive_record.entities.join(', ')}\\.`));
  if (!rr.markPaymentReceived) want(['set_payment_status', 'create_payment'], /You cannot mark a payment received\./);
  if (rr.add_task_assignee?.selfNeedsManagerOrCreator) want(['add_task_assignee'], /You can add yourself only to tasks you manage or created\./);
  if (!rr.seeMoney) want(['get_record', 'find_project', 'find_milestone'], /Prices are hidden for your role\./);

  const tools = registeredWithDescriptions(r);
  const lines: string[] = [];
  for (const [tool, desc] of tools) {
    const expected = exp.filter(([t]) => t === tool);
    for (const [, re] of expected) if (!re.test(desc)) problems.push(`${r}/${tool}: missing limit sentence ${re}`);
    const n = limitSentences(r, tool).length;
    if (n !== expected.length) problems.push(`${r}/${tool}: ${n} limit sentence(s) but rules explain ${expected.length}`);
    if (n === 0 && desc !== base.get(tool)) problems.push(`${r}/${tool}: description changed although the role has no limit on it`);
    if (n > 0) lines.push(`    ${tool}: ${desc.split('\n\n').pop()}`);
  }
  if (tools.size > 0) console.log(`  ${r} (${lines.length} tool(s) with limits)${lines.length ? '\n' + lines.join('\n') : ''}`);
}
rule('super_admin descriptions carry no limit sentence', [...base.values()].every((d) => !d.includes('Limits for your role')));

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
