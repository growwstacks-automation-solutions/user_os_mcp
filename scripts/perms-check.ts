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
//     be offered it, not even admins).

import { readFileSync } from 'node:fs';

import type { Identity } from '../src/auth';
import type { Env } from '../src/db';
import { ALL_TOOLS, ROLE_RULES, ROLE_TOOLS, toolsForRole } from '../src/permissions';
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

if (problems.length > 0) {
  console.error(`\nFAILED — ${problems.length} problem(s):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('\nOK — every allowed name matches a registered tool.');
