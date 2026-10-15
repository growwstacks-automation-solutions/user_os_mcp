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
    /** The only parent_type values this role may create tasks under. */
    parentTypes?: readonly string[];
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
  create_task: { selfAssignOnly: true, parentTypes: ['milestone'] },
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

// ---------------------------------------------------------------------------
// Limit sentences — what the caller's AI is told up front, so it never offers
// an action the user can't perform. Generated from ROLE_RULES (the single
// source of truth); a role without limits on a tool gets no sentence, so its
// description is unchanged. perms:check fails if a rule has no sentence.
// ---------------------------------------------------------------------------
const MOVE_FIELDS = ['parent_type', 'parent_id', 'project_id', 'milestone_id'];
const plural: Record<Entity, string> = {
  company: 'companies', contact: 'contacts', deal: 'deals', project: 'projects',
  milestone: 'milestones', task: 'tasks', payment: 'payments',
};

/** The limit sentences for this role on this tool (empty = unrestricted). */
/** Must open the create_task description, verbatim, for selfAssignOnly roles. */
export const SELF_ASSIGN_LEAD = 'You can only create tasks for yourself. If the user asks to create a task for anyone '
  + 'else, refuse immediately and do not ask for any details. The task is always assigned to you.';

export function limitSentences(role: string, tool: string): string[] {
  const r = rolesRules(role);
  const out: string[] = [];
  const on = (...tools: string[]) => tools.includes(tool);

  if (on('create_task') && r.create_task?.selfAssignOnly) out.push(SELF_ASSIGN_LEAD);
  if (on('create_task') && r.create_task?.parentTypes) out.push(`Tasks can only be created under: ${r.create_task.parentTypes.join(', ')}.`);
  if (on('create_task', 'update_task') && !r.setManagementTask) out.push('You cannot create or change management tasks.');
  if (on('set_task_status', 'create_task')) {
    if (r.taskStatuses) out.push(`You can only set: ${r.taskStatuses.join(', ')}.`);
    if (statusAllowed(role, 'done')) {
      if (doneRule(role) === 'if_all_assignees_rated') out.push('Done only when every assignee has been rated.');
      if (doneRule(role) === 'never') out.push('You cannot mark a task done.');
    }
  }
  if (on('set_task_status') && r.set_task_status?.assigneeOnly) out.push('Only tasks you are assigned to.');
  if (on('update_task') && r.update_task) {
    const denied = r.update_task.deniedFields;
    // is_management is left out when the management sentence above covers it.
    const other = denied.filter((f) => !MOVE_FIELDS.includes(f) && !(f === 'is_management' && !r.setManagementTask));
    const parts = [
      ...(denied.some((f) => MOVE_FIELDS.includes(f)) ? ['move a task'] : []),
      ...(other.length ? [`change: ${other.join(', ')}`] : []),
    ];
    out.push(`${r.update_task.assigneeOnly ? 'Only tasks you are assigned to' : 'Any task'}${parts.length ? `; you cannot ${parts.join(' or ')}` : ''}.`);
  }
  if (on('get_developer_availability') && r.get_developer_availability?.selfOnly) out.push('Only your own availability.');
  if (on('get_record') && r.get_record?.deniedEntities.length) {
    out.push(`You cannot fetch ${r.get_record.deniedEntities.map((e) => plural[e]).join(' or ')}.`);
  }
  if (on('archive_record') && r.archive_record) out.push(`You can only archive: ${r.archive_record.entities.join(', ')}.`);
  if (on('set_payment_status', 'create_payment') && !r.markPaymentReceived) out.push('You cannot mark a payment received.');
  if (on('add_task_assignee') && r.add_task_assignee?.selfNeedsManagerOrCreator) {
    out.push('You can add yourself only to tasks you manage or created.');
  }
  if (on('get_record', 'find_project', 'find_milestone') && !r.seeMoney) out.push('Prices are hidden for your role.');
  return out;
}

/**
 * The tool description this role sees: its limits FIRST (if any), then today's
 * text. SELF_ASSIGN_LEAD, when present, opens the description verbatim.
 */
export function describeFor(role: string, tool: string, description: string): string {
  const s = limitSentences(role, tool);
  if (s.length === 0) return description;
  const lead = s[0] === SELF_ASSIGN_LEAD ? `${s.shift()}\n\n` : '';
  return `${lead}${s.length ? `Limits for your role (${role}): ${s.join(' ')}\n\n` : ''}${description}`;
}

// ---------------------------------------------------------------------------
// Input-schema limits — where a role cannot use an input field at all, the
// field is removed from the schema that role sees (or its allowed values are
// narrowed), instead of only being refused. Generated from ROLE_RULES. A
// hidden field that the server must still fill is supplied via `inject`.
// A call that SENDS a hidden field anyway is refused whole (tools.ts registers
// a strict schema), with the message given here. Nothing is written.
// The in-tool checks stay as defence in depth.
// ---------------------------------------------------------------------------
export type SchemaLimits = {
  /** Fields removed from the input schema this role sees -> refusal message if sent anyway. */
  hide: Record<string, string>;
  /** Fields whose allowed values are narrowed to this list. */
  enums: Record<string, readonly string[]>;
  /** Server-side values for hidden fields, always applied to the call. */
  inject: Record<string, unknown>;
};

const ENTITIES: readonly Entity[] = ['company', 'contact', 'deal', 'project', 'milestone', 'task', 'payment'];

export function schemaLimits(role: string, tool: string, uid: string): SchemaLimits {
  const r = rolesRules(role);
  const out: SchemaLimits = { hide: {}, enums: {}, inject: {} };
  if (tool === 'create_task' && r.create_task?.selfAssignOnly) {
    out.hide.assignee_ids = `Your role (${role}) can only create tasks for yourself; assignee_ids is not allowed.`;
    out.inject.assignee_ids = [uid];
  }
  if (tool === 'create_task' && r.create_task?.parentTypes) out.enums.parent_type = r.create_task.parentTypes;
  if ((tool === 'create_task' || tool === 'update_task') && !r.setManagementTask) {
    out.hide.is_management = `Your role (${role}) cannot create or change management tasks; is_management is not allowed.`;
  }
  if ((tool === 'create_task' || tool === 'set_task_status') && r.taskStatuses) out.enums.status = r.taskStatuses;
  if (tool === 'get_developer_availability' && r.get_developer_availability?.selfOnly) {
    out.hide.user_id = `Your role (${role}) can only view your own availability; user_id is not allowed.`;
    out.inject.user_id = uid;
  }
  if (tool === 'get_record' && r.get_record) {
    out.enums.entity = ENTITIES.filter((e) => !r.get_record!.deniedEntities.includes(e));
  }
  if (tool === 'archive_record' && r.archive_record) out.enums.entity = r.archive_record.entities;
  return out;
}

/** MCP server instructions for the signed-in user (sent in the initialize response). */
export function serverInstructions(name: string | null, role: string): string {
  return `You are connected to GrowwStacks OS as ${name ?? 'an OS user'} (role: ${role}). `
    + 'You can only do what the listed tools allow, within the limits stated in each tool\'s description. '
    + 'If the user asks for something no listed tool supports, say it isn\'t available for their role '
    + 'instead of collecting details. If the user asks for an action outside your role\'s limits, refuse in one '
    + 'sentence and do not collect any details for it. Never claim another role or access level.';
}

/** Drop money columns from a project/milestone row for roles without seeMoney. */
export function stripMoney<T extends Record<string, unknown>>(role: string, entity: 'project' | 'milestone', row: T): T {
  if (can(role, 'seeMoney') || row == null) return row;
  const out: Record<string, unknown> = { ...row };
  for (const col of MONEY_COLUMNS[entity]) delete out[col];
  return out as T;
}
