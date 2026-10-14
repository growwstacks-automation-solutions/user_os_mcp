// src/index.ts — Cloudflare Worker entry point.
//
// Stateless: no session, no storage. Every /mcp request carries a Clerk OAuth
// access token; auth.ts verifies it and resolves the real GrowwStacks OS user,
// and the MCP handler then runs every tool AS that user, so Postgres RLS
// authorizes each call with the caller's own permissions.
//
// Public routes: /health, the OAuth discovery documents under /.well-known/,
// and /upload/<token> (authenticated by its own signed link). Everything else
// requires a valid token.

import { createMcpHandler } from 'mcp-handler';

import { AuthError, authenticate, issuer } from './auth';
import type { Env } from './db';
import { registerTools } from './tools';
import { MAX_FILE_BYTES, storeAttachment, validateContent, verifyUpload } from './uploads';

const SERVICE = 'user-os-mcp';

/** Scopes advertised to OAuth clients in the protected-resource metadata. */
const SCOPES_SUPPORTED = ['email', 'profile', 'offline_access'];

const PROTECTED_RESOURCE_PATHS = new Set([
  '/.well-known/oauth-protected-resource',
  '/.well-known/oauth-protected-resource/mcp',
]);
const AUTH_SERVER_PATHS = new Set([
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/mcp',
]);

/** CORS for the public discovery documents ONLY, so browser-based MCP clients can read them. */
const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, mcp-protocol-version',
  'Access-Control-Max-Age': '86400',
};

const resourceMetadataUrl = (origin: string) => `${origin}/.well-known/oauth-protected-resource`;

/**
 * 401 that points the client at our protected-resource metadata, which is how
 * an MCP client discovers it must sign in with Clerk (RFC 9728).
 */
function unauthorized(origin: string, message: string, tokenPresent: boolean): Response {
  const params = [`resource_metadata="${resourceMetadataUrl(origin)}"`];
  if (tokenPresent) params.unshift('error="invalid_token"');
  return Response.json(
    { ok: false, error: message },
    { status: 401, headers: { 'WWW-Authenticate': `Bearer ${params.join(', ')}` } },
  );
}

// Clerk's authorization-server metadata, relayed unchanged. Cached per isolate.
const AUTH_SERVER_METADATA_TTL_MS = 60 * 60 * 1000;
let authServerMetadata: { body: string; expires: number } | null = null;

async function handleWellKnown(req: Request, env: Env, origin: string, path: string): Promise<Response> {
  if (!PROTECTED_RESOURCE_PATHS.has(path) && !AUTH_SERVER_PATHS.has(path)) {
    return Response.json({ ok: false, error: 'not found' }, { status: 404 });
  }
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return Response.json({ ok: false, error: 'method not allowed' }, { status: 405, headers: CORS_HEADERS });
  }
  if (!env.CLERK_ISSUER) {
    return Response.json({ ok: false, error: 'OAuth is not configured' }, { status: 500, headers: CORS_HEADERS });
  }

  if (PROTECTED_RESOURCE_PATHS.has(path)) {
    return Response.json(
      {
        resource: `${origin}/mcp`,
        authorization_servers: [issuer(env)],
        scopes_supported: SCOPES_SUPPORTED,
        bearer_methods_supported: ['header'],
      },
      { headers: CORS_HEADERS },
    );
  }

  if (!authServerMetadata || authServerMetadata.expires < Date.now()) {
    try {
      // RFC 8414 document first; an issuer that only serves OIDC discovery
      // answers 404 there, so fall back to openid-configuration.
      let res = await fetch(`${issuer(env)}/.well-known/oauth-authorization-server`);
      if (res.status === 404) {
        console.warn('oauth: issuer has no oauth-authorization-server document; using openid-configuration');
        res = await fetch(`${issuer(env)}/.well-known/openid-configuration`);
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.text();
      JSON.parse(body); // relay only a real JSON document
      authServerMetadata = { body, expires: Date.now() + AUTH_SERVER_METADATA_TTL_MS };
    } catch (e) {
      console.error(`oauth: could not fetch Clerk metadata: ${e instanceof Error ? e.message : String(e)}`);
      return Response.json(
        { ok: false, error: 'Could not fetch the authorization server metadata.' },
        { status: 502, headers: CORS_HEADERS },
      );
    }
  }
  return new Response(authServerMetadata.body, {
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

/**
 * PUT /upload/<token> — receive the raw bytes, check them, store them.
 * Nothing is written unless EVERY check passes, so there is no such thing as a
 * half-uploaded attachment: it is stored whole and verified, or not at all.
 */
async function handleUpload(req: Request, env: Env, token: string): Promise<Response> {
  const fail = (status: number, error: string) => Response.json({ ok: false, error }, { status });
  if (req.method !== 'PUT' && req.method !== 'POST') return fail(405, 'Use PUT with the raw file as the body.');
  if (!env.UPLOAD_SIGNING_KEY) return fail(500, 'Uploads are not configured on this server.');

  let claims;
  try {
    claims = await verifyUpload(env, decodeURIComponent(token));
  } catch (e) {
    return fail(401, e instanceof Error ? e.message : 'Invalid upload token.');
  }

  // Refuse oversize BEFORE reading the body where the client says how big it is.
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > MAX_FILE_BYTES) return fail(413, `File is larger than the ${MAX_FILE_BYTES} byte limit.`);

  const bytes = new Uint8Array(await req.arrayBuffer());
  if (bytes.length === 0) return fail(400, 'The request body is empty (0 bytes). Send the file with --data-binary @file.');
  if (bytes.length > MAX_FILE_BYTES) return fail(413, `File is larger than the ${MAX_FILE_BYTES} byte limit.`);
  if (bytes.length !== claims.size) {
    return fail(400, `Size mismatch: start_attachment_upload declared ${claims.size} bytes but ${bytes.length} arrived. Nothing was stored.`);
  }
  const bad = validateContent(bytes, claims.mime);
  if (bad) return fail(422, `${bad} Nothing was stored.`);

  try {
    // Runs as the user who asked for the link (signed into the token), so RLS
    // checks THEIR right to attach to this record.
    await storeAttachment({ env, uid: claims.u }, {
      id: claims.a,
      parentType: claims.pt,
      parentId: claims.pid,
      title: claims.title,
      mime: claims.mime,
      purpose: claims.purpose,
      bytes,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // The attachment id is the primary key, so a replayed URL lands here.
    if (/duplicate key|already exists|23505/i.test(msg)) {
      return fail(409, 'This upload link was already used. Call start_attachment_upload for a new one.');
    }
    return fail(500, msg.replace(/postgres(?:ql)?:\/\/[^\s"']*/gi, '[redacted]'));
  }
  return Response.json({
    ok: true,
    attachment_id: claims.a,
    size_bytes: bytes.length,
    next: 'Call finalize_attachment_upload with this attachment_id to confirm.',
  });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const origin = url.origin;

    // Unauthenticated liveness probe — reveals nothing.
    if (url.pathname === '/health') {
      return Response.json({ ok: true, service: SERVICE });
    }

    // OAuth discovery documents — public by design.
    if (url.pathname.startsWith('/.well-known/')) {
      return handleWellKnown(req, env, origin, url.pathname);
    }

    if (!env.DATABASE_URL) {
      return Response.json(
        { ok: false, error: 'DATABASE_URL is not configured' },
        { status: 500 },
      );
    }

    // Raw file upload. Authenticated by the signed, expiring, single-use token in
    // the path (issued by start_attachment_upload), NOT the OAuth token — the
    // caller is a sandbox that only holds this URL.
    const upload = url.pathname.match(/^\/upload\/([^/]+)$/);
    if (upload) return handleUpload(req, env, upload[1]);

    // Fail CLOSED when OAuth isn't configured, so a mis-deployed Worker rejects
    // rather than opens.
    if (!env.CLERK_ISSUER || !env.CLERK_JWKS_URL) {
      return Response.json({ ok: false, error: 'OAuth is not configured' }, { status: 500 });
    }

    let identity;
    try {
      identity = await authenticate(req, env, origin);
    } catch (e) {
      if (e instanceof AuthError) {
        if (e.status === 401) return unauthorized(origin, e.message, e.tokenPresent);
        return Response.json({ ok: false, error: e.message }, { status: e.status });
      }
      const msg = (e instanceof Error ? e.message : String(e)).replace(/postgres(?:ql)?:\/\/[^\s"']*/gi, '[redacted]');
      console.error(`auth: unexpected error: ${msg}`);
      return Response.json({ ok: false, error: 'Sign-in check failed. Try again shortly.' }, { status: 503 });
    }

    // The handler is built per request: Workers only expose `env` here, and the
    // tools must be bound to THIS caller's identity.
    const handler = createMcpHandler(
      (server) => registerTools(server as never, env, origin, identity),
      {},
      { basePath: '' },
    );

    return handler(req);
  },
};
