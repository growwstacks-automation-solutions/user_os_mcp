// src/permissions.ts — which MCP tools each OS role may use, and the extra
// limits some roles have inside a tool. Aligned with the OS portal's role rules.
//
// The role always comes from identity.role (read from `users` at sign-in by
// auth.ts), NEVER from tool input. Deny by default: a role that is not listed
// below gets no tools, and auth.ts refuses its sign-in with a 403. Inside
// ROLE_RULES, a missing key always means "not allowed" / "no extra power".
//
// This is a second layer on top of Postgres RLS, not a replacement: RLS still
// decides which ROWS a user can see or change. This file decides which TOOLS
// they are offered at all, and narrows a few tools further for some roles.
//
// scripts/perms-check.ts (`npm run perms:check`) fails if a name here does not
// match a registered tool, or a registered tool is missing from ALL_TOOLS, and
// tests every rule below for an allowed and a refused case.

/** Every tool registered in tools.ts. Keep in sync (perms:check enforces it). */
export const ALL_TOOLS = [
  // Companies
  'create_company', 'update_company', 'find_company', 'set_company_owner', 'list_industries',
  // Create
  'create_contact', 'create_deal', 'create_project', 'create_task', 'create_milestone', 'create_payment',
  // Field edits
  'update_contact', 'update_deal', 'update_project', 'update_milestone', 'update_task', 'update_payment',
  // Status changes
  'set_task_status', 'set_project_status', 'set_payment_status', 'set_deal_stage',
  // Reads
  'get_statuses', 'get_payments', 'get_developer_availability', 'list_tasks', 'get_record', 'get_credentials',
  // Archive
  'archive_record',
  // People
  'add_task_assignee', 'remove_task_assignee', 'add_task_manager', 'remove_task_manager',
  'add_project_member', 'remove_project_member', 'set_contact_owner',
  // Attachments
  'add_attachment', 'start_attachment_upload', 'finalize_attachment_upload', 'list_attachments',
  // Task discussion
  'add_task_comment', 'get_task_discussion',
  // Lookups
  'list_pipelines', 'list_apps', 'search_contacts', 'find_user', 'find_deal', 'find_project', 'find_milestone',
] as const;

export type ToolName = (typeof ALL_TOOLS)[number];

const SALES_TOOLS: readonly ToolName[] = [
  'find_company', 'create_company', 'update_company', 'set_company_owner', 'list_industries',
  'search_contacts', 'create_contact', 'update_contact', 'set_contact_owner',
  'find_deal', 'create_deal', 'update_deal', 'set_deal_stage', 'list_pipelines',
  'find_user', 'find_project', 'get_record', 'get_statuses',
  'add_attachment', 'start_attachment_upload', 'finalize_attachment_upload', 'list_attachments',
  'archive_record',  // deals only — see ROLE_RULES.sales
  'get_credentials', // metadata only; secrets never leave the OS app
];

const DELIVERY_TOOLS: readonly ToolName[] = [
  'find_user', 'find_project', 'find_milestone', 'get_record', 'get_statuses', 'list_apps',
  'list_tasks', 'get_task_discussion', 'add_task_comment', 'set_task_status', 'update_task',
  'create_task', // self-assigned only — see DELIVERY_RULES
  'get_developer_availability', 'get_credentials',
  'add_attachment', 'start_attachment_upload', 'finalize_attachment_upload', 'list_attachments',
];

/** Role -> tools it may use. A role missing here gets nothing. */
export const ROLE_TOOLS: Readonly<Record<string, readonly ToolName[]>> = {
  super_admin: ALL_TOOLS,
  admin: ALL_TOOLS,
  pm: ALL_TOOLS, // RLS limits pm to their own projects' data
  sales: SALES_TOOLS,
  developer: DELIVERY_TOOLS,
  operations: DELIVERY_TOOLS, // same tools and rules as developer
  // internal, finance, viewer: no MCP access (sign-in refused with 403)
};

// ---------------------------------------------------------------------------
// Per-role rules. tools.ts enforces these BEFORE any write. A missing key
// means "not allowed" (capabilities) or "no extra limit" (per-tool limits).
// ---------------------------------------------------------------------------
export type Entity = 'company' | 'contact' | 'deal' | 'project' | 'milestone' | 'task' | 'payment';

export type ToolRules = {
  /** Task statuses this role may set (set_task_status, create_task). Missing = any the DB allows. */
  taskStatuses?: readonly string[];
  /** Marking a task done. Missing = never. */
  markTaskDone?: 'always' | 'if_all_assignees_rated';
  /** May set or clear is_management on a task. */
  setManagementTask?: true;
  /** May set a payment's status to "received". */
  markPaymentReceived?: true;
  /** Sees money columns (MONEY_COLUMNS) on project and milestone results. */
  seeMoney?: true;

  create_task?: {
    /** assignee_ids must be exactly [the caller]. */
    selfAssignOnly: true;
  };
  update_task?: {
    /** Only on tasks where the caller is an assignee. */
    assigneeOnly: true;
    /** Fields this role may never change or clear. */
    deniedFields: readonly string[];
  };
  set_task_status?: {
    /** Only on tasks where the caller is an assignee. */
    assigneeOnly: true;
  };
  get_developer_availability?: {
    /** The caller can only see their own availability. */
    selfOnly: true;
  };
  get_record?: {
    /** Entities this role may not fetch. */
    deniedEntities: readonly Entity[];
  };
  archive_record?: {
    /** The only entities this role may archive. */
    entities: readonly Entity[];
  };
  add_task_assignee?: {
    /** Assigning YOURSELF needs you to already be a manager or the creator of the task. */
    selfNeedsManagerOrCreator: true;
  };
};

const DELIVERY_RULES: ToolRules = {
  taskStatuses: ['todo', 'in_progress', 'qa_review'],
  create_task: { selfAssignOnly: true },
  update_task: {
    assigneeOnly: true,
    // Moving a task, and the management flag, stay with admins/pms.
    deniedFields: ['parent_type', 'parent_id', 'project_id', 'milestone_id', 'is_management'],
  },
  set_task_status: { assigneeOnly: true },
  get_developer_availability: { selfOnly: true },
  get_record: { deniedEntities: ['deal', 'payment'] },
};

/** Role -> rules. A role missing here has no capabilities and no extra limits. */
export const ROLE_RULES: Readonly<Record<string, ToolRules>> = {
  super_admin: {
    markTaskDone: 'always',
    setManagementTask: true,
    markPaymentReceived: true,
    seeMoney: true,
  },
  admin: {
    markTaskDone: 'if_all_assignees_rated',
    setManagementTask: true,
    markPaymentReceived: true,
    seeMoney: true,
  },
  pm: {
    markTaskDone: 'if_all_assignees_rated',
    seeMoney: true,
    add_task_assignee: { selfNeedsManagerOrCreator: true },
  },
  sales: {
    archive_record: { entities: ['deal'] },
    get_record: { deniedEntities: ['payment'] },
  },
  developer: DELIVERY_RULES,
  operations: DELIVERY_RULES,
};

/** Money columns hidden from roles without seeMoney. projects has none today. */
export const MONEY_COLUMNS: Readonly<Record<'project' | 'milestone', readonly string[]>> = {
  project: [],
  milestone: ['price', 'currency'],
};

/**
 * Fields no tool may ever return, for any role: work_ratings values and who gave
 * them (plus the rating rollups). tools.ts drops these keys from every result.
 */
export const NEVER_RETURN_FIELDS: ReadonlySet<string> = new Set([
  'timely_delivery', 'responsiveness', 'requirement_understanding', 'quality', 'problem_solving',
  'rater_user_id', 'ratee_user_id', 'rater_type', 'stars', 'feedback', 'rating_basis',
  'avg_rating', 'performance_star_rating', 'rating_notes',
]);

// ---------------------------------------------------------------------------
// Lookups (pure — perms:check tests them without a database)
// ---------------------------------------------------------------------------
export function toolsForRole(role: string): readonly ToolName[] {
  return Object.hasOwn(ROLE_TOOLS, role) ? ROLE_TOOLS[role] : [];
}

export function isToolAllowed(role: string, tool: string): boolean {
  return (toolsForRole(role) as readonly string[]).includes(tool);
}

function rolesRules(role: string): ToolRules {
  return Object.hasOwn(ROLE_RULES, role) ? ROLE_RULES[role] : {};
}

export function rulesFor<K extends keyof ToolRules>(role: string, key: K): ToolRules[K] | undefined {
  return rolesRules(role)[key];
}

type Capability = 'setManagementTask' | 'markPaymentReceived' | 'seeMoney';
export function can(role: string, cap: Capability): boolean {
  return rolesRules(role)[cap] === true;
}

/** May this role set a task to this status at all (before the done rule)? */
export function statusAllowed(role: string, status: string): boolean {
  const list = rolesRules(role).taskStatuses;
  return !list || list.includes(status);
}

export function doneRule(role: string): 'always' | 'if_all_assignees_rated' | 'never' {
  return rolesRules(role).markTaskDone ?? 'never';
}

export function recordAllowed(role: string, entity: Entity): boolean {
  return !rolesRules(role).get_record?.deniedEntities.includes(entity);
}

export function archiveAllowed(role: string, entity: Entity): boolean {
  const only = rolesRules(role).archive_record?.entities;
  return !only || only.includes(entity);
}

/** Drop money columns from a project/milestone row for roles without seeMoney. */
export function stripMoney<T extends Record<string, unknown>>(role: string, entity: 'project' | 'milestone', row: T): T {
  if (can(role, 'seeMoney') || row == null) return row;
  const out: Record<string, unknown> = { ...row };
  for (const col of MONEY_COLUMNS[entity]) delete out[col];
  return out as T;
}
