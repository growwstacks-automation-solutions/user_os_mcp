// src/permissions.ts — which MCP tools each OS role may use, and the extra
// limits some roles have inside a tool.
//
// The role always comes from identity.role (read from `users` at sign-in by
// auth.ts), NEVER from tool input. Deny by default: a role that is not listed
// below gets no tools, and auth.ts refuses its sign-in with a 403.
//
// This is a second layer on top of Postgres RLS, not a replacement: RLS still
// decides which ROWS a user can see or change. This file decides which TOOLS
// they are offered at all, and narrows a few tools further for some roles.
//
// scripts/perms-check.ts (`npm run perms:check`) fails if a name here does not
// match a registered tool, or a registered tool is missing from ALL_TOOLS.

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
];

const DELIVERY_TOOLS: readonly ToolName[] = [
  'find_user', 'find_project', 'find_milestone', 'get_record', 'get_statuses', 'list_apps',
  'list_tasks', 'get_task_discussion', 'add_task_comment', 'set_task_status', 'update_task',
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
  internal: DELIVERY_TOOLS,
  // operations: [],  // placeholder — no MCP access yet
  // finance, viewer: no MCP access yet (no current users have these roles)
};

// ---------------------------------------------------------------------------
// Per-tool limits for a role. A tool with no entry here runs unrestricted
// (RLS still applies). tools.ts enforces these BEFORE any write.
// ---------------------------------------------------------------------------
export type ToolRules = {
  update_task?: {
    /** The only fields this role may change or clear. */
    allowedFields: readonly string[];
    /** Only on tasks where the caller is an assignee. */
    assigneeOnly: boolean;
  };
  set_task_status?: {
    /** Only on tasks where the caller is an assignee. */
    assigneeOnly: boolean;
    /** Statuses this role may set. null = any status RLS allows. */
    allowedStatuses: readonly string[] | null;
  };
  get_developer_availability?: {
    /** The caller can only see their own availability. */
    selfOnly: boolean;
  };
};

const DELIVERY_RULES: ToolRules = {
  update_task: {
    allowedFields: ['time_reported_hours', 'loom_url', 'delivery_state'],
    assigneeOnly: true,
  },
  set_task_status: {
    assigneeOnly: true,
    allowedStatuses: null, // unrestricted for now; list values here to narrow it
  },
  get_developer_availability: { selfOnly: true },
};

/** Role -> limits inside tools. A role missing here has no extra limits. */
export const ROLE_RULES: Readonly<Record<string, ToolRules>> = {
  developer: DELIVERY_RULES,
  internal: DELIVERY_RULES,
};

export function toolsForRole(role: string): readonly ToolName[] {
  return Object.hasOwn(ROLE_TOOLS, role) ? ROLE_TOOLS[role] : [];
}

export function isToolAllowed(role: string, tool: string): boolean {
  return (toolsForRole(role) as readonly string[]).includes(tool);
}

export function rulesFor<K extends keyof ToolRules>(role: string, tool: K): ToolRules[K] | undefined {
  return Object.hasOwn(ROLE_RULES, role) ? ROLE_RULES[role][tool] : undefined;
}
