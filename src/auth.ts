// src/auth.ts — who is calling? Clerk OAuth access token -> GrowwStacks OS user.
//
// Every /mcp request carries a Clerk OAuth access token (an RS256 JWT). We:
//   1. verify it (signature via Clerk's JWKS, issuer, expiry, audience = this
//      server's /mcp resource, and the client_id + scope claims that only OAuth
//      access tokens have — a Clerk SESSION token lacks them and is refused);
//   2. look up the account's primary email with the Clerk Backend API (access
//      tokens carry no email), accepting it only when Clerk says it is verified;
//   3. find the ONE active OS user with that email.
//
// The result is the identity every tool then runs as (db.ts sets it as
// app.current_user_id), so RLS sees the real person. There is NO fallback to
// the service account: any failure here ends the request.

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

import { asService, type Env } from './db';

export type Identity = {
  /** users.id — what app.current_user_id is set to for every query. */
  id: string;
  role: string;
  email: string;
  name: string | null;
};

/**
 * A refusal with a status and a message that is safe to show the caller.
 * 401 = no usable token (the client should sign in again); 403 = signed in, but
 * not an active OS user; 503 = we could not complete the check (Clerk or config).
 */
export class AuthError extends Error {
  constructor(
    readonly status: 401 | 403 | 503,
    message: string,
    /** True when a token WAS sent (adds error="invalid_token" to the 401). */
    readonly tokenPresent = false,
  ) {
    super(message);
  }
}

// One JWKS fetcher per URL for the life of the isolate. jose caches the keys
// and refetches on an unknown `kid`, so key rotation needs no redeploy.
const jwksByUrl = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jwks(url: string) {
  let set = jwksByUrl.get(url);
  if (!set) {
    set = createRemoteJWKSet(new URL(url));
    jwksByUrl.set(url, set);
  }
  return set;
}

/** Clerk user id (sub) -> verified primary email, for 5 minutes. Successes only. */
const EMAIL_TTL_MS = 5 * 60 * 1000;
const emailCache = new Map<string, { email: string; expires: number }>();

/** The issuer as configured, without a trailing slash. */
export function issuer(env: Env): string {
  return env.CLERK_ISSUER.replace(/\/+$/, '');
}

/** Verify the bearer token and resolve the OS user. Throws AuthError on any failure. */
export async function authenticate(req: Request, env: Env, origin: string): Promise<Identity> {
  const header = req.headers.get('authorization') ?? '';
  const match = header.match(/^Bearer\s+(\S+)\s*$/i);
  if (!match) throw new AuthError(401, 'Sign in required: send an OAuth access token as "Authorization: Bearer <token>".');

  const payload = await verifyAccessToken(match[1], env, `${origin}/mcp`);
  const email = await primaryEmail(env, payload.sub as string);
  return osUserForEmail(env, email);
}

async function verifyAccessToken(token: string, env: Env, resource: string): Promise<JWTPayload> {
  const invalid = () => new AuthError(401, 'Invalid or expired access token. Sign in again.', true);

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks(env.CLERK_JWKS_URL), {
      issuer: issuer(env),
      algorithms: ['RS256'],
      requiredClaims: ['sub', 'exp'],
      clockTolerance: 5,
    }));
  } catch (e) {
    console.warn(`auth: token rejected: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`);
    throw invalid();
  }

  // OAuth access tokens carry client_id and scope; Clerk session tokens do not.
  if (typeof payload.client_id !== 'string' || payload.client_id === '' || typeof payload.scope !== 'string') {
    console.warn('auth: token rejected: no client_id/scope claim (not an OAuth access token, e.g. a Clerk session token)');
    throw invalid();
  }

  // Audience is checked here rather than in jwtVerify so a MISSING aud gets its own log line.
  if (payload.aud === undefined) {
    console.warn(
      `auth: token rejected: no aud claim. The client must send resource=${resource} in its OAuth `
      + 'authorization and token requests so Clerk binds the token to this server.',
    );
    throw invalid();
  }
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(resource)) {
    console.warn(`auth: token rejected: aud ${JSON.stringify(auds)} does not include ${resource}`);
    throw invalid();
  }
  return payload;
}

type ClerkUser = {
  primary_email_address_id: string | null;
  email_addresses?: { id: string; email_address: string; verification: { status: string } | null }[];
};

async function primaryEmail(env: Env, sub: string): Promise<string> {
  const hit = emailCache.get(sub);
  if (hit && hit.expires > Date.now()) return hit.email;

  if (!env.CLERK_SECRET_KEY) {
    console.error('auth: CLERK_SECRET_KEY is not configured');
    throw new AuthError(503, 'Sign-in is not configured on this server.');
  }

  let res: Response;
  try {
    res = await fetch(`https://api.clerk.com/v1/users/${encodeURIComponent(sub)}`, {
      headers: { Authorization: `Bearer ${env.CLERK_SECRET_KEY}` },
    });
  } catch (e) {
    console.error(`auth: Clerk Backend API unreachable: ${e instanceof Error ? e.message : String(e)}`);
    throw new AuthError(503, 'Could not reach the sign-in service. Try again shortly.');
  }
  if (res.status === 404) {
    console.warn('auth: token sub has no Clerk user (deleted account?)');
    throw new AuthError(401, 'Your sign-in account no longer exists. Sign in again.', true);
  }
  if (!res.ok) {
    console.error(`auth: Clerk Backend API returned HTTP ${res.status}`);
    throw new AuthError(503, 'Could not reach the sign-in service. Try again shortly.');
  }

  const user = (await res.json()) as ClerkUser;
  const primary = user.email_addresses?.find((e) => e.id === user.primary_email_address_id);
  if (!primary) throw new AuthError(403, 'Your sign-in account has no primary email address.');
  if (primary.verification?.status !== 'verified') {
    throw new AuthError(403, 'Your primary email address is not verified. Verify it, then sign in again.');
  }

  const email = primary.email_address.trim();
  emailCache.set(sub, { email, expires: Date.now() + EMAIL_TTL_MS });
  return email;
}

async function osUserForEmail(env: Env, email: string): Promise<Identity> {
  // users is RLS-protected, so this ONE read runs as the service account. Named
  // columns only — the table also holds salary.
  const rows = await asService<{
    id: string; role: string; email: string; full_name: string | null; status: string;
  }>(env, (sql) => sql`
    SELECT id, role::text AS role, email, full_name, status::text AS status
    FROM users
    WHERE lower(email) = lower(${email}) AND archived_at IS NULL
  `);

  const notFound = 'No active GrowwStacks OS account matches your sign-in email. Ask an admin to check your OS user.';
  if (rows.length === 0) throw new AuthError(403, notFound);
  if (rows.length > 1) {
    console.error(`auth: ${rows.length} OS users share one email; refusing (ids: ${rows.map((r) => r.id).join(', ')})`);
    throw new AuthError(403, 'More than one OS account matches your sign-in email. Ask an admin to fix it.');
  }
  const u = rows[0];
  if (u.status === 'left_org') throw new AuthError(403, notFound);
  return { id: u.id, role: u.role, email: u.email, name: u.full_name };
}
