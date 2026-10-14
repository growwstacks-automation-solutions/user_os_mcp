# os-mcp: Knowledge Transfer

> **Who this is for:** Claude (in claude.ai chat or another assistant) helping the GrowwStacks team work on this repo or use the connector. It covers what the system is, how it is built, every tool it exposes, the rules it enforces, and the traps found along the way.
>
> **Snapshot:** repo `growwstacks-automation-solutions/os-mcp`, branch `OS-MCP`, last commit `5c9dd3b` (2026-10-01, "presigned file upload for attachments, with content validation"). Source of truth is the code in `src/`. Where the README disagrees with the code, the code wins (see §12).

---

## 1. What this is, in one paragraph

**os-mcp** is a remote **MCP (Model Context Protocol) server** that lets Claude read and write data in **GrowwStacks OS**, GrowwStacks' internal operating system. GrowwStacks OS is a separate Next.js-style app (not in this repo) covering CRM, delivery and finance: companies, contacts, deals, projects, milestones, tasks, payments, attachments, credentials and developer availability. This server does **not** call the OS app's API. It runs on **Cloudflare Workers**, connects **directly to the OS's Neon Postgres database** and re-implements the matching OS server actions (`lib/actions/*.ts` in the OS repo) as MCP tools. All permissions are enforced by **Postgres Row-Level Security (RLS)**: every query runs as a specific OS user. In claude.ai it shows up as the **"OS MCP"** connector (tool names `mcp__claude_ai_OS_MCP__<tool>`).

---

## 2. Repo layout

```
os-mcp/
├── src/
│   ├── index.ts      (~125 lines)  Worker entry: routing, auth, /upload endpoint
│   ├── db.ts         (~115 lines)  The ONLY file that touches Postgres (asUser* helpers)
│   ├── tools.ts      (~2700 lines) All 48 MCP tools + validation helpers
│   └── uploads.ts    (~270 lines)  File validation, signed upload URLs, blob storage
├── scripts/
│   └── create-mcp-user.mjs         One-off: inserts the "MCP (System)" user row
├── .github/workflows/deploy.yml    CI: push to OS-MCP → typecheck → wrangler deploy
├── wrangler.jsonc                  Worker config (name os-mcp, nodejs_compat)
├── package.json                    deps: @neondatabase/serverless, mcp-handler, zod
├── tsconfig.json                   strict, ES2022, Bundler resolution
├── .dev.vars.example               Template for local secrets
└── README.md                       Partly stale (see §12)
```

`.gitignore` also excludes `GROWWSTACKS_OS_CONTEXT.md`, an internal OS architecture brief that is kept local and never committed. If someone has it, it is the best reference for the OS schema.

---

## 3. Tech stack

| Layer | Choice |
|---|---|
| Runtime | Cloudflare Workers (stateless; `compatibility_date` 2026-06-04, `nodejs_compat` flag needed by Neon driver) |
| MCP framework | `mcp-handler` (`createMcpHandler`), Streamable HTTP transport |
| Validation | `zod` v3, one schema per tool; the JSON Schema advertised to Claude comes from it |
| Database | Neon serverless Postgres via `@neondatabase/serverless` **HTTP driver** (`neon()` + `sql.transaction([...])`) |
| Language | TypeScript (strict), no build output; `wrangler` bundles |
| CI/CD | GitHub Actions → `cloudflare/wrangler-action@v3` |

Scripts: `npm run dev` (wrangler dev, reads `.dev.vars`), `npm run typecheck` (tsc --noEmit), `npm run deploy`.

---

## 4. Request flow (end to end)

```
Claude (claude.ai connector / any MCP client)
   │  POST https://<worker>/mcp   Authorization: Bearer <MCP_AUTH_TOKEN>  (or x-api-key)
   ▼
src/index.ts  fetch()
   ├─ GET /health                → {"ok":true,"service":"os-mcp"}   (no auth)
   ├─ !MCP_AUTH_TOKEN            → 401  (fails CLOSED if secret missing)
   ├─ !DATABASE_URL              → 500
   ├─ /upload/<signed-token>     → handleUpload()  (auth = signed token, NOT bearer)
   ├─ bearer/x-api-key mismatch  → 401  (constant-time compare)
   └─ createMcpHandler(registerTools(server, env, url.origin), {}, {basePath:''})
         │  built PER REQUEST because Workers only expose env inside fetch()
         ▼
src/tools.ts  tool handler, wrapped in guard()
   ├─ zod validates + coerces args
   ├─ business checks (creator allowlist, 100% shares, on-hold reason …)
   └─ db.ts asUser / asUserMany / asUserWithReason / asNamedUser
         ▼
Neon Postgres (role app_user)
   BEGIN;
     select set_config('app.current_user_id', <actor uuid>, true);
     [select set_config('app.audit_reason', <reason>, true);]   -- archives only
     <the real statement(s)>
   COMMIT;
   → RLS policies + triggers (display_id, spine caches, audit, payment %) do the rest
```

`guard()` turns any thrown error into an MCP `isError` result reading `ERROR: …`. It **redacts connection strings and credentials** (the Neon driver puts the full DSN, password included, into some error messages) and prefixes RLS denials (`42501`) with "Refused by the database (RLS)". Successful results are `JSON.stringify(data, null, 2)` as one text block.

---

## 5. Security model (the most important section)

### 5.1 `DATABASE_URL` must be the `app_user` role, never the Neon owner
No table in the OS schema sets `FORCE ROW LEVEL SECURITY`. An owner connection therefore **silently bypasses all 55 RLS policies**, and `app.current_user_id` stops doing anything. `app_user` keeps RLS on.

### 5.2 Identity = one service account
- Every call acts as **`GS_ACTOR_UID`**. In production this is the dedicated user **`U-SYS-MCP` / "MCP (System)"**, id `00000000-0000-0000-0000-0000000000fe`, role `admin`, created by `scripts/create-mcp-user.mjs`.
- If `GS_ACTOR_UID` is unset, the code falls back to the OS **SYSTEM** user `…0000ff` ("Slack Sync (System)", from OS migration 0023, also `admin`).
- There is **no per-caller scoping**. Every MCP caller gets the same admin view, so `get_payments` returns *all* payments, not the PM-scoped subset the OS UI shows.
- Because the actor is `admin` and not `super_admin`, **salary data stays hidden**, and **credential secrets stay unreachable** (`credentials.secret_ref` is REVOKED from all app roles in OS migration 0005).

### 5.3 The identity GUC must be set in the same transaction as the query
The Neon HTTP driver is stateless, so each call is its own HTTP request. `db.ts` always batches `set_config('app.current_user_id', …, true)` (transaction-local) **with** the real statement inside `sql.transaction([...])`, which means the identity can't leak between requests. This mirrors the OS app's own `lib/db.ts`.

`db.ts` helpers:

| Helper | Use |
|---|---|
| `asUser(env, sql => …)` | One statement as the service actor. Returns its rows. |
| `asUserMany(env, sql => [...])` | Several statements in one transaction; returns the **last** statement's rows. Needed when a later statement's RLS must see an earlier insert (tasks, milestones, payments, attachments). |
| `asUserWithReason(env, reason, …)` | Also sets `app.audit_reason` so the `fn_audit` trigger records why. Used by every archive. |
| `asNamedUser(env, uid, …)` | Acts as a **specific human**. Used only by `add_task_comment`, because the RLS policy pins `sender_user_id = fn_me()`. `uid` must come from the allowlist. |

### 5.4 Other guarantees
- Every SQL value goes through a Neon tagged template, so everything is parameterised. Column names in UPDATEs are hard-coded literals.
- There is **no generic "run SQL" tool**.
- **No hard deletes.** "Delete" means archive (`archived_at = now()` plus an audited reason). The only `DELETE` statements remove join-table rows (assignees, managers, project members), which the OS also allows.
- `display_id` (e.g. `T-6192`) and the **spine caches** (`contact_id`, `company_id`, `project_id`, `milestone_id` on child rows) are **trigger-maintained** and never set by this code.
- Not-found and RLS-denied look the same on purpose (empty result or a generic message).

### 5.5 Auth on the wire
- `/mcp` accepts either `Authorization: Bearer <MCP_AUTH_TOKEN>` or `x-api-key: <MCP_AUTH_TOKEN>`, compared in constant time.
- `/upload/<token>` uses an HMAC-signed, 15-minute, single-use token instead (see §8). The HMAC key is derived from `MCP_AUTH_TOKEN`, so **rotating the bearer token invalidates any outstanding upload URLs**.

---

## 6. GrowwStacks OS domain model (as this code sees it)

```
companies (the ACCOUNT)  ── account_owner_id → users
   └─ contacts (a PERSON; CRM hub) ── contact_owners (join) + primary_owner_id (cached pointer)
        └─ deals ── pipeline_id + stage_id (truth) + legacy `stage` enum; deal_owners (join)
             ├─ projects ── project_members (join: pm|developer), project_manager_id, apps_used text[]
             │    └─ milestones (billable line items: price, currency)
             │         └─ tasks ── task_assignees (join), task_managers (join), primary_pm_id (cached)
             └─ payments ── payment_developers (join: percent_share, must total 100)
attachments        polymorphic (parent_type, parent_id) on any entity; blobs in attachment_blobs (base64)
conversation_entries  polymorphic thread; a task's "Discussion" lives here
credentials        contact_id and/or credential_links (polymorphic); secret_ref never readable
users              role (admin, super_admin, pm, developer, sales, finance …), status (incl. left_org)
user_availability  per user per date: working_hours, status (incl. absent, first_half, second_half)
availability_allocations  hours per project per availability day
pipelines / pipeline_stages, project_app_catalog, industries   controlled vocabularies
audit_log          written by fn_audit trigger; reason from app.audit_reason GUC
```

Key enums and vocabularies:
- **contact_status** (a person): `prospect, active_client, partner, on_hold, churned`
- **company_type** (an account): `prospect, client, partner, past_client`. This is a different vocabulary from contact_status.
- **company_size**: `1-10, 11-50, 50-200, 200+`
- **milestone_status**: `not_started, in_progress, in_review, client_pending, on_hold, done`
- **priority**: `low, medium, high`. This is not a task status.
- **project_status** (live from DB): `upcoming, in_progress, client_pending, on_hold, payment_pending, handover, client_review, completed, internal, lost`
- **task_status** (live from DB): `todo, in_progress, client_review, client_pending, internal_action, qa_review, stuck, on_hold, done, …`
- **payment_status**: live from DB (default on create is `forecast`, and `received` exists)
- **entity_type** (polymorphic parent): `company, contact, deal, project, milestone, task, payment`
- Deal stages are **rows** (`pipeline_stages`), not an enum. `get_statuses('deal')` returns them.

Tasks have `parent_type ∈ {milestone, deal, payment}`, usually `milestone`. `is_management` marks management-stream tasks, which `list_tasks` hides by default.

---

## 7. The full tool catalog (48 tools)

Legend: **R** = required, **A/S** = "ask-or-skip" (required, but accepts the literal `"skip"`; see §9), opt = optional.

### 7.1 Companies
| Tool | Inputs | Notes |
|---|---|---|
| `create_company` | name R; type R (company_type); website A/S; industry A/S (name from `list_industries`); company_size A/S; location A/S; account_owner_id A/S; about opt | Location `"Indore, MP, India"` is split into city/state/country, filled from the end (a single part goes to country). Industry is resolved to `industry_id` (`companies.industry` is a trigger cache), and unknown names are rejected with the valid list. |
| `update_company` | company_id + any fields; `clear_fields[]` | Only the fields passed change. `clear_fields` nulls columns. |
| `find_company` | query, limit | Matches name/website/display_id; returns owner name and contact_count. Use before create to avoid duplicates. |
| `set_company_owner` | company_id, user_id | |
| `list_industries` | – | Controlled vocabulary. |

### 7.2 Contacts, deals, projects, milestones, tasks: create
| Tool | Inputs | Notes |
|---|---|---|
| `create_contact` | full_name R; status A/S (skip → prospect); primary_owner_id A/S (skip → MCP account owns it, usually wrong); company_id A/S; email, phone opt | Inserts the contact **and** a `contact_owners` row in one CTE. |
| `create_deal` | name, contact_id, pipeline_id, stage_id R; deal_value, currency, initial_deal_amount, lead_type, source, primary_owner_id, close_date all A/S; payment_type opt | Verifies the stage belongs to the pipeline. Sets legacy `stage` enum = the stage's name if that is a valid `deal_stage` label, else `'new'`. Inserts a `deal_owners` row. **Never infer `source` or `lead_type`.** |
| `create_project` | name R; deal_id, contact_id, status (skip → upcoming), estimated_hours, start_date, estimated_completion_date all A/S; project_manager_id opt; apps opt | `apps` are normalised to `project_app_catalog` casing (`monday` → `Monday`), and unknown names are **rejected** (the OS UI silently drops them). If deal_id is given, contact_id is ignored because the trigger caches the client from the deal. |
| `create_milestone` | name, project_id R; status A/S (skip → not_started); estimated_hours A/S; target_date, price, currency opt | One milestone per call. Inserted without RETURNING, then selected back. |
| `create_task` | title, parent_id R; parent_type (default milestone); manager_ids, assignee_ids, status, priority, plan_due_date, start_date, estimated_hours, requirement all A/S; **acting_user_id R; creator_quote R** | See §9.2 for the creator rules. Inserts the task, then the manager and assignee join rows, then selects back a full record with names, assignees and managers. First manager = `primary_pm_id`. |
| `create_payment` | deal_id, amount, currency, submitted_amount R; status opt (default forecast); project_id, milestone_id, payment_type, payment_date, billing_date, transaction_ref, invoice_no, note, received_amount_inr, platform_name, billing_type (fixed/hourly, default fixed), hours_logged, hourly_rate opt; developers[{user_id, percent_share}] opt | Developers are de-duplicated by user. Shares must total exactly 100: the tool checks first for a clear message, and the DB trigger `fn_check_payment_percent` is the real gate. `created_by` = MCP actor. |

### 7.3 Updates (partial; only what you pass changes, `clear_fields[]` nulls)
`update_contact`, `update_deal`, `update_project`, `update_milestone`, `update_task`, `update_payment`.
- Use `set_deal_stage` to change a deal's stage, not `update_deal`.
- `update_project.apps` **replaces** the whole list (validated).
- Use `set_project_status`, `set_task_status` and `set_payment_status` for status changes; the update tools don't touch status (except `update_contact.status` and `update_milestone.status`, which they do allow).
- `update_task` also covers `delivery_state` (not_delivered/delivered), execution dates, `time_reported_hours`, `loom_url`, `requirement` and `details`.
- Each returns `{updated:[fields], cleared:[fields], <entity>:{…}}` and errors if nothing was passed.

### 7.4 Status changes
| Tool | Rule |
|---|---|
| `set_task_status(task_id, status)` | status must be a `task_status` value |
| `set_project_status(project_id, status, on_hold_reason?)` | `on_hold` **requires** a reason; any other status clears `on_hold_reason` |
| `set_payment_status(payment_id, status)` | `received` requires `amount > 0` **and** `received_amount_inr > 0` (mirrors the OS `assertReceivable`; DB trigger `trg_payment_received_admin` is the real gate) |
| `set_deal_stage(deal_id, stage_id)` | Stage must belong to the deal's pipeline. Syncs the legacy enum when the name matches and otherwise leaves it unchanged. |

### 7.5 Reads
| Tool | Notes |
|---|---|
| `get_statuses(entity)` | Deal → pipeline stages; others → live `pg_enum` values. ⚠ `company` is accepted but has no enum mapping (returns empty; see §12). |
| `get_record(entity, id)` | Full row plus joined names. Task records include created_by_name, primary_pm_name, assignees[] and managers[]. Returns `null` when not found or not visible. |
| `list_tasks` | Filters: assignee_id, manager_id, created_by, project_id, milestone_id, status[], due_before, search (title/display_id), include_management (default false), `full` (default false; adds requirement, details and the other large fields), limit ≤500 (default 100). Sorted by due date (nulls last), then newest. Always includes created_by_name, assignees and managers. |
| `get_payments` | Filters: status[], deal_id[], project_id[] (matches payment.project_id **or** via milestone), date_from/date_to (on payment_date), search, limit ≤500. Joins deal, milestone, project and contact names. |
| `get_developer_availability(date_from, date_to, user_id?)` | Active developers (role=developer, not left_org). For each day: working = stored `working_hours` (default 8), halved for `first_half`/`second_half` and set to 0 for `absent`; allocated = sum of `availability_allocations`; available = max(0, working − allocated). ⚠ This is deliberately different from the OS helper `workingForStatus()`, which uses constants and doesn't zero out `absent`. |
| `get_credentials(parent_type ∈ contact/project/milestone, parent_id)` | **Metadata only**: label, login_url, username, 2FA info, access flags, notes. No tool ever returns a secret, by design. Secrets are revealed only in the OS app, which logs the access. |

### 7.6 People / assignment (join tables, never a single FK)
`add_task_assignee`, `remove_task_assignee`, `add_task_manager`, `remove_task_manager`, `add_project_member(role: pm|developer)`, `remove_project_member`, `set_contact_owner` (writes the `contact_owners` row and updates the cached `contacts.primary_owner_id`). The add tools are idempotent (`ON CONFLICT DO NOTHING`, returning `{already_assigned:true}` and similar).

### 7.7 Archive
`archive_record(entity, id, reason 3–1000 chars)` sets `archived_at` and writes the reason to `audit_log` through `app.audit_reason`. Archive children before parents. It errors if the record is already archived.

### 7.8 Attachments: see §8
`add_attachment`, `start_attachment_upload`, `finalize_attachment_upload`, `list_attachments` (never returns file bytes).

### 7.9 Task discussion
| Tool | Notes |
|---|---|
| `add_task_comment(task_id, body, author_id, author_quote)` | Posts **as the named person** (via `asNamedUser`), with the same allowlist and quote check as the task creator (§9.2), plus: the quote must name **exactly one** permitted person. Writes a `conversation_entries` row in the same shape the OS UI uses: `channel='slack'`, `direction='outbound'`, `sender_user_id=fn_me()`, `metadata={"source":"mcp"}`. |
| `get_task_discussion(task_id, limit≤500)` | The most recent `limit` comments, returned oldest first, with sender_name and a `posted_via_mcp` flag. |

### 7.10 Lookups (they exist because the create tools need UUIDs)
`list_pipelines`, `list_apps`, `list_industries`, `search_contacts` (name/email/display_id, plus phone matching on the last digits when the query has ≥7 digits), `find_user` (query and/or exact role; excludes left_org), `find_deal`, `find_project`, `find_milestone` (optionally within a project), `find_company`.

---

## 8. File attachments (why there are two routes)

**Problem:** a tool call is text the model types. A 470 KB image is about 630,000 base64 characters, which a model can't reproduce faithfully. It truncates the data or sends a shell command instead. A real incident produced a 141-byte "PNG" on task **T-6192**, and a 14-byte shell command was once saved as a PNG. All of this code exists so that a broken file is **refused, never stored as a success**.

**Route A: small inline** (`add_attachment` with `file_base64`, ≤ 256 KB). The base64 is decoded strictly (it rejects non-base64, wrong padding or a shell command), the MIME type must be on the allowlist, and the content is validated.

**Route B: presigned upload** (any real file, ≤ 5 MB):
1. `start_attachment_upload(parent_type, parent_id, file_name, mime_type, file_size_bytes, purpose?)` checks `fn_can_edit(parent)` first, then returns `attachment_id`, `upload_url` (`<origin>/upload/<token>`, valid 15 minutes) and a ready-made `curl -X PUT --data-binary @file` command. `file_size_bytes` must be measured from the real file (e.g. `wc -c`).
2. The caller's **code sandbox** runs the curl command. claude.ai needs code execution with network access to the Worker's domain. Without a sandbox, Claude should ask the user for a link instead.
3. The Worker (`PUT /upload/<token>`) verifies the HMAC and expiry, rejects declared or actual size > 5 MB, rejects an empty body, requires **actual size == declared size**, validates the content, then stores. Nothing is written unless every check passes. A replayed URL hits the primary-key conflict and gets 409 ("already used").
4. `finalize_attachment_upload(attachment_id)` re-reads the blob from the DB, re-decodes it, checks the size and re-validates the content. If that fails, Claude must tell the user it failed.

**Content validation** (`validateContent`) checks both ends of the file, because truncation keeps a valid header:
PNG = signature plus an `IEND` trailer · JPEG = `FFD8FF` … `FFD9` (trailing zero padding allowed) · GIF = `GIF87a/89a` … `0x3B` · WebP = RIFF/WEBP with header length == byte count · PDF = `%PDF-` with `%%EOF` in the last 1 KB.
Allowed MIME types: `image/png, image/jpeg, image/gif, image/webp, application/pdf`.

**Storage:** an `attachments` row (`kind='file'`, `url='/api/attachments/<id>'` so it opens in the OS app, `uploaded_by` = actor) plus an `attachment_blobs` row (`data_base64`), in two statements in one transaction (the blob's RLS policy has to see the parent row). Links are stored with `kind='link'`. Files live **in Postgres**, which is why there's a 5 MB cap.

The upload token is `base64url(JSON claims).base64url(HMAC-SHA256)`, keyed by `"os-mcp-upload:" + MCP_AUTH_TOKEN`. The claims are `{a: attachment_id, pt, pid, title, mime, size, purpose, exp}`.

---

## 9. "Make Claude ask": the input-design philosophy

An MCP tool can't prompt a human. The team found that **descriptions alone don't make a model stop and ask**: it fills the field with whatever is nearest. What does work:

### 9.1 Ask-or-skip fields
Fields the team never wants silently defaulted are **required**, but accept the literal string `"skip"` (which maps to null, `[]` or a documented default). The model has to make a conscious choice: either a real value from the user or an explicit skip. Missing fields fail validation, Claude sees which field and the legal values, and asks the user.

Helpers: `askOrSkip`, `askOrSkipArray`, `askOrSkipNumber`, `val()`, `arrVal()`.

**Input coercion** (this only widens what parses): many MCP clients send arrays as JSON strings (`"[\"uuid\"]"`), single values, comma lists, numbers as `"2"` and booleans as `"true"`. `coerceArray`, `coerceNumber` (only a string that is entirely a number; `"2 hours"` is still rejected) and `coerceBoolean` fix these before zod runs. This was the fix for `assignee_ids`, `manager_ids` and `estimated_hours` being unusable from the connector.

### 9.2 Task creator / comment author: allowlist + verbatim-quote evidence
This went through about 8 commits of hardening. The current design:
- **Only two people** may be recorded as a task's `created_by` or post a comment:
  - **Faizal Khan** = `00b5232b-2f84-4b7e-ae98-26ccf683e7c5`
  - **Manish Mandot** = `4e0d5b3b-fe89-485b-be6a-5909cf272d5c`

  (`TASK_CREATORS` in `tools.ts`. To add someone: add a line and redeploy.)
- `acting_user_id` / `author_id` is a **closed zod enum**: those two ids plus the sentinel `"not_stated_by_user"`.
- `creator_quote` / `author_quote` must be the user's **verbatim words** naming the creator, or `"none"`.
- The server rejects the call, with the exact question to put to the user, when:
  - the sentinel or `"none"` is passed → *"Who should I record as the creator of this task — Faizal Khan or Manish Mandot?"*
  - the quote, **after stripping assignee/manager/owner/PM/reviewer phrases** (`withoutRoleMentions`), does not name the chosen person by first name. So "assigned to Faizal" can't stand in for "created by Faizal".
  - (comments only) the quote names both people.
- There is **no fallback to the system account** for the creator. Nothing is written on any failure path.
- Attribution only: `created_by` is a column value. RLS still authorizes the task insert as the MCP actor. Comments are different: they really do run *as* that person (`asNamedUser`), because the RLS policy requires `sender_user_id = fn_me()`.

Other "never infer" rules in the descriptions: deal `source` and `lead_type`, contact/deal owner, deal stage (don't default to the first stage), project apps.

---

## 10. Non-obvious DB behaviours reproduced from the OS

1. **Tasks and milestones can't use `INSERT … RETURNING`.** Their SELECT policy (`fn_can_see`) is self-referential, so the new row is invisible to RETURNING and the insert fails RLS even for an admin. The code generates the UUID client-side (`crypto.randomUUID()`), inserts without RETURNING, then SELECTs back in the same transaction (`asUserMany`). Payments and attachments use the same pattern.
2. **Attachment blob insert** needs the parent `attachments` row to be visible, which means a separate statement and not a CTE.
3. **Dates come back as `to_char(…,'YYYY-MM-DD')` text.** The Neon driver otherwise parses `date` into a JS Date at UTC midnight, which displays a **day early in IST (+05:30)**. Every RETURNING/SELECT shadows date columns with text versions.
4. **Deals have two stage fields:** `pipeline_id`/`stage_id` (the source of truth) and a legacy `stage` (`deal_stage` enum), kept in sync by stage name.
5. **Contacts have two owner representations:** the `contact_owners` join table (authoritative) and `contacts.primary_owner_id` (cached pointer). Write both. Deals likewise have `deal_owners` plus `primary_owner_id`.
6. **`companies.industry` is a cache.** Set `industry_id`.
7. **`search_contacts` phone match** uses `regexp_replace(phone,'\\D','','g')`. The doubled backslash in TS produces SQL `'\D'`.

---

## 11. Known differences from the OS app

1. **No task-assignment notifications.** The OS `createTask` sends in-app and Teams pings, but MCP-created tasks are silent.
2. **The "admin/PM must assign at least one developer to a payment" rule isn't enforced.** It lives only in OS TypeScript, not the DB.
3. **Availability math differs** (absent = 0, half-days halve the stored hours). See §7.5.
4. **Visibility is admin-wide** for every caller (§5.2).
5. **Unknown app names are rejected**, where the OS UI silently drops them.

---

## 12. Gaps, inconsistencies and likely bugs (verify before relying on them)

- **README is stale.** It says "Tools (29)" and "all 13 tools registered"; the code registers **48**. It says `create_project.apps` is required, but in code it's optional (only status, dates, etc. are ask-or-skip). It lists required fields per tool that have since grown (see §7). It says "the four write tools have not been run". Trust the code.
- **`get_statuses('company')`** is allowed by the zod enum, but `company` has no entry in the enum-name map, so it queries `typname = undefined` and returns an empty list. The fix would be to map it to `company_type`.
- **`.dev.vars.example` default `GS_ACTOR_UID` is `…fe`** (MCP user), while the code's fallback is **`…ff`** (SYSTEM) and the README example shows `…ff`. Production should be `…fe`.
- **`deploy.yml` comment says "Push to main"**, but the trigger is branch **`OS-MCP`**. `OS-MCP` is the only branch, the default branch, and also the deploy branch: **every push to it goes live**, and the typecheck is the only gate. There are no tests.
- `update_contact` description says "Cannot blank a field out", but it does support `clear_fields`.
- `create_deal` has dead fallback code for a missing `stage_id` (the schema already requires it).
- `creatorNamedIn` matches by **first-name substring**. That's fine for the two current names, but it would misfire if two allowlisted people shared a first name.
- `create_payment` doesn't take `contact_id`; `payments.contact_id` is presumably trigger-cached from the deal (spine).
- `add_project_member` casts `role` to `user_role`, which works because `pm` and `developer` are `user_role` labels.

---

## 13. Configuration and deployment

**Secrets** (Worker secrets in production, `.dev.vars` locally; never commit, paste or log them):
| Name | Meaning |
|---|---|
| `DATABASE_URL` | Neon connection string for **`app_user`** (`postgresql://app_user:…@….neon.tech/…?sslmode=require`) |
| `MCP_AUTH_TOKEN` | Shared bearer token for `/mcp`; also the HMAC key seed for upload URLs |
| `GS_ACTOR_UID` | Acting user UUID (production `00000000-0000-0000-0000-0000000000fe`) |

`wrangler.jsonc` deliberately has **no `vars` block**. Set them with `wrangler secret put <NAME>`; they persist across deploys.

**CI** (`.github/workflows/deploy.yml`): runs on push to `OS-MCP` or a manual dispatch, with concurrency group `deploy-os-mcp` (no cancel). Steps: Node 22 → `npm ci` → `npm run typecheck` → `wrangler-action`. Repo secrets: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. The Worker is published on `workers.dev` (`workers_dev: true`), named `os-mcp`.

**Local:**
```bash
npm install
cp .dev.vars.example .dev.vars   # fill in real values
npm run dev                       # http://127.0.0.1:8787
npm run typecheck
curl -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```
⚠ Local dev runs against the **production** Neon database. Write tools create real rows, so test on records you're willing to archive.

**One-off:** `node scripts/create-mcp-user.mjs` (reads `.dev.vars`) inserts the `U-SYS-MCP` user idempotently, acting as SYSTEM, which satisfies RLS on `users`. It has already been run.

---

## 14. How to add or change a tool (house conventions)

1. Add a `server.tool(name, description, zodShape, guard(async (a) => …))` in `registerTools` (`src/tools.ts`), in the section it belongs to.
2. **All DB access goes through `db.ts` helpers.** Never call `neon()` elsewhere, and never interpolate strings into SQL.
3. Make fields the team must decide into **required or ask-or-skip**, not optional. Put the legal values and "ASK THE USER" in the description. Wrap numbers, booleans and arrays with `num()` / `bool()` / `optArray()` / `askOrSkip*` so stringified client input parses.
4. Never set `display_id` or spine cache columns. Use client-generated UUIDs plus insert-then-select for RLS-self-referential tables.
5. Return dates as `to_char(..., 'YYYY-MM-DD')`. Cast enums to `::text` in output.
6. Writes that can affect zero rows should throw a clear "not permitted or not found" error.
7. Deletions are archives with a reason (`asUserWithReason`).
8. Mirror the matching OS server action's logic, and note any deliberate divergence in the README's "Known differences".
9. `npm run typecheck`, then push to `OS-MCP`, which deploys to production.

---

## 15. Commit history (oldest → newest), useful for understanding why

| Commit | Change |
|---|---|
| `ce27ab4` | Initial MCP server |
| `2f0240e` | CI deploys from `OS-MCP` branch |
| `72ea15d` | Companies, attachments, credentials metadata, ask-or-skip fields |
| `f0caab1` | Fix task assignee arrays; expose created_by |
| `c108b0c` → `f3febd9` | Six iterations hardening the **task creator**: ask instead of defaulting to system, allowlist (Faizal/Manish), remove skip fallback, sentinel, verbatim quote, strip assignee/manager mentions |
| `0719179` | Accept numbers and booleans sent as strings |
| `aca78f4` | Task discussion: add/read comments |
| `5c9dd3b` | Presigned file upload with content validation (after the truncated-PNG incident) |

---

## 16. Quick usage recipes (for Claude using the connector)

- **New task:** `find_project` → `find_milestone(project_id)` → `find_user` for manager(s) and assignee(s) → ask the user for anything missing (priority, dates, hours, requirement, **creator**) → `create_task`.
- **New deal:** `search_contacts` (or `create_company` → `create_contact`) → `list_pipelines` → ask stage/value/currency/source/lead type/owner/close date → `create_deal`.
- **Record a payment:** `find_deal` → (optional) `find_project`/`find_milestone` → `find_user` for developers with shares totalling 100 → `create_payment`. To mark it received: `update_payment(received_amount_inr…)` → `set_payment_status('received')`.
- **Attach a screenshot:** in a sandbox, `wc -c file` → `start_attachment_upload` → run the curl command → `finalize_attachment_upload`. With no sandbox, use `add_attachment` with a `url` link.
- **Who's free next week?** `get_developer_availability(date_from, date_to)`.
- **"Delete" anything:** `archive_record` with a reason (children first).
- **Passwords:** not possible through this MCP. Use `get_credentials` for metadata and point the user to the OS app to reveal the secret.
