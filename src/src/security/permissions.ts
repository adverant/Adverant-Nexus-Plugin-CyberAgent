/**
 * Permission Definitions
 *
 * Granular permissions for Role-Based Access Control (RBAC)
 */

/**
 * Permission categories
 */
export enum PermissionCategory {
  SCANS = 'scans',
  MALWARE = 'malware',
  WORKFLOWS = 'workflows',
  NEXUS = 'nexus',
  REPORTS = 'reports',
  ADMIN = 'admin',
  APPROVALS = 'approvals'
}

/**
 * Permission actions
 */
export enum PermissionAction {
  READ = 'read',
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  EXECUTE = 'execute',
  APPROVE = 'approve',
  EXPORT = 'export',
  MANAGE = 'manage'
}

/**
 * Permission definition
 */
export interface Permission {
  id: string;
  category: PermissionCategory;
  action: PermissionAction;
  resource: string;
  description: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * All system permissions
 */
export const PERMISSIONS: Record<string, Permission> = {
  // Scan Permissions
  'scans:read': {
    id: 'scans:read',
    category: PermissionCategory.SCANS,
    action: PermissionAction.READ,
    resource: 'scans',
    description: 'View scan jobs and results',
    risk_level: 'low'
  },
  'scans:create': {
    id: 'scans:create',
    category: PermissionCategory.SCANS,
    action: PermissionAction.CREATE,
    resource: 'scans',
    description: 'Create new scan jobs',
    risk_level: 'medium'
  },
  'scans:execute': {
    id: 'scans:execute',
    category: PermissionCategory.SCANS,
    action: PermissionAction.EXECUTE,
    resource: 'scans',
    description: 'Execute scan jobs',
    risk_level: 'high'
  },
  'scans:delete': {
    id: 'scans:delete',
    category: PermissionCategory.SCANS,
    action: PermissionAction.DELETE,
    resource: 'scans',
    description: 'Delete scan jobs',
    risk_level: 'medium'
  },
  'scans:export': {
    id: 'scans:export',
    category: PermissionCategory.SCANS,
    action: PermissionAction.EXPORT,
    resource: 'scans',
    description: 'Export scan results',
    risk_level: 'low'
  },

  // Malware Analysis Permissions
  'malware:read': {
    id: 'malware:read',
    category: PermissionCategory.MALWARE,
    action: PermissionAction.READ,
    resource: 'malware',
    description: 'View malware samples and analysis results',
    risk_level: 'medium'
  },
  'malware:create': {
    id: 'malware:create',
    category: PermissionCategory.MALWARE,
    action: PermissionAction.CREATE,
    resource: 'malware',
    description: 'Upload malware samples',
    risk_level: 'high'
  },
  'malware:execute': {
    id: 'malware:execute',
    category: PermissionCategory.MALWARE,
    action: PermissionAction.EXECUTE,
    resource: 'malware',
    description: 'Execute malware in sandbox',
    risk_level: 'critical'
  },
  'malware:delete': {
    id: 'malware:delete',
    category: PermissionCategory.MALWARE,
    action: PermissionAction.DELETE,
    resource: 'malware',
    description: 'Delete malware samples',
    risk_level: 'high'
  },
  'malware:export': {
    id: 'malware:export',
    category: PermissionCategory.MALWARE,
    action: PermissionAction.EXPORT,
    resource: 'malware',
    description: 'Export malware analysis results',
    risk_level: 'medium'
  },

  // Workflow Permissions
  'workflows:read': {
    id: 'workflows:read',
    category: PermissionCategory.WORKFLOWS,
    action: PermissionAction.READ,
    resource: 'workflows',
    description: 'View workflows and executions',
    risk_level: 'low'
  },
  'workflows:create': {
    id: 'workflows:create',
    category: PermissionCategory.WORKFLOWS,
    action: PermissionAction.CREATE,
    resource: 'workflows',
    description: 'Create custom workflows',
    risk_level: 'medium'
  },
  'workflows:execute': {
    id: 'workflows:execute',
    category: PermissionCategory.WORKFLOWS,
    action: PermissionAction.EXECUTE,
    resource: 'workflows',
    description: 'Execute workflows',
    risk_level: 'high'
  },
  'workflows:delete': {
    id: 'workflows:delete',
    category: PermissionCategory.WORKFLOWS,
    action: PermissionAction.DELETE,
    resource: 'workflows',
    description: 'Delete workflows',
    risk_level: 'medium'
  },
  'workflows:approve': {
    id: 'workflows:approve',
    category: PermissionCategory.WORKFLOWS,
    action: PermissionAction.APPROVE,
    resource: 'workflows',
    description: 'Approve workflow steps',
    risk_level: 'high'
  },

  // Nexus Integration Permissions
  'nexus:read': {
    id: 'nexus:read',
    category: PermissionCategory.NEXUS,
    action: PermissionAction.READ,
    resource: 'nexus',
    description: 'Query Nexus intelligence',
    risk_level: 'low'
  },
  'nexus:execute': {
    id: 'nexus:execute',
    category: PermissionCategory.NEXUS,
    action: PermissionAction.EXECUTE,
    resource: 'nexus',
    description: 'Trigger Nexus analysis',
    risk_level: 'medium'
  },
  'nexus:manage': {
    id: 'nexus:manage',
    category: PermissionCategory.NEXUS,
    action: PermissionAction.MANAGE,
    resource: 'nexus',
    description: 'Manage Nexus integrations',
    risk_level: 'high'
  },

  // Report Permissions
  'reports:read': {
    id: 'reports:read',
    category: PermissionCategory.REPORTS,
    action: PermissionAction.READ,
    resource: 'reports',
    description: 'View reports',
    risk_level: 'low'
  },
  'reports:create': {
    id: 'reports:create',
    category: PermissionCategory.REPORTS,
    action: PermissionAction.CREATE,
    resource: 'reports',
    description: 'Generate reports',
    risk_level: 'low'
  },
  'reports:export': {
    id: 'reports:export',
    category: PermissionCategory.REPORTS,
    action: PermissionAction.EXPORT,
    resource: 'reports',
    description: 'Export reports',
    risk_level: 'low'
  },

  // Approval Permissions
  'approvals:approve': {
    id: 'approvals:approve',
    category: PermissionCategory.APPROVALS,
    action: PermissionAction.APPROVE,
    resource: 'approvals',
    description: 'Approve security operations',
    risk_level: 'critical'
  },

  // Admin Permissions
  'admin:users': {
    id: 'admin:users',
    category: PermissionCategory.ADMIN,
    action: PermissionAction.MANAGE,
    resource: 'users',
    description: 'Manage users',
    risk_level: 'high'
  },
  'admin:roles': {
    id: 'admin:roles',
    category: PermissionCategory.ADMIN,
    action: PermissionAction.MANAGE,
    resource: 'roles',
    description: 'Manage roles and permissions',
    risk_level: 'critical'
  },
  'admin:targets': {
    id: 'admin:targets',
    category: PermissionCategory.ADMIN,
    action: PermissionAction.MANAGE,
    resource: 'targets',
    description: 'Manage authorized targets',
    risk_level: 'high'
  },
  'admin:config': {
    id: 'admin:config',
    category: PermissionCategory.ADMIN,
    action: PermissionAction.MANAGE,
    resource: 'config',
    description: 'Manage system configuration',
    risk_level: 'critical'
  },
  'admin:audit': {
    id: 'admin:audit',
    category: PermissionCategory.ADMIN,
    action: PermissionAction.READ,
    resource: 'audit',
    description: 'View audit logs',
    risk_level: 'medium'
  }
};

/**
 * Role definitions with permissions
 */
export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * System roles
 */
export const ROLES: Record<string, Role> = {
  viewer: {
    id: 'viewer',
    name: 'Viewer',
    description: 'Read-only access to scans and reports',
    permissions: [
      'scans:read',
      'malware:read',
      'workflows:read',
      'nexus:read',
      'reports:read'
    ],
    risk_level: 'low'
  },

  analyst: {
    id: 'analyst',
    name: 'Security Analyst',
    description: 'Can create and execute scans, analyze results',
    permissions: [
      'scans:read',
      'scans:create',
      'scans:execute',
      'scans:export',
      'malware:read',
      'malware:create',
      'malware:export',
      'workflows:read',
      'workflows:execute',
      'nexus:read',
      'nexus:execute',
      'reports:read',
      'reports:create',
      'reports:export'
    ],
    risk_level: 'medium'
  },

  senior_analyst: {
    id: 'senior_analyst',
    name: 'Senior Security Analyst',
    description: 'Full analyst capabilities plus malware execution and workflow approval',
    permissions: [
      'scans:read',
      'scans:create',
      'scans:execute',
      'scans:delete',
      'scans:export',
      'malware:read',
      'malware:create',
      'malware:execute',
      'malware:delete',
      'malware:export',
      'workflows:read',
      'workflows:create',
      'workflows:execute',
      'workflows:delete',
      'workflows:approve',
      'nexus:read',
      'nexus:execute',
      'reports:read',
      'reports:create',
      'reports:export',
      'approvals:approve'
    ],
    risk_level: 'high'
  },

  admin: {
    id: 'admin',
    name: 'Administrator',
    description: 'Full system access including user and configuration management',
    permissions: Object.keys(PERMISSIONS),
    risk_level: 'critical'
  }
};

/**
 * Check if role has permission
 */
export function hasPermission(role: string, permission: string): boolean {
  const roleObj = ROLES[role];
  if (!roleObj) {
    return false;
  }
  return roleObj.permissions.includes(permission);
}

/**
 * Check if user has any of the required permissions
 */
export function hasAnyPermission(role: string, permissions: string[]): boolean {
  return permissions.some(permission => hasPermission(role, permission));
}

/**
 * Check if user has all required permissions
 */
export function hasAllPermissions(role: string, permissions: string[]): boolean {
  return permissions.every(permission => hasPermission(role, permission));
}

/**
 * Get all permissions for a role
 */
export function getRolePermissions(role: string): Permission[] {
  const roleObj = ROLES[role];
  if (!roleObj) {
    return [];
  }
  return roleObj.permissions.map(permId => PERMISSIONS[permId]).filter(Boolean);
}

/**
 * Get permissions by category
 */
export function getPermissionsByCategory(category: PermissionCategory): Permission[] {
  return Object.values(PERMISSIONS).filter(p => p.category === category);
}

/**
 * Get permissions by risk level
 */
export function getPermissionsByRiskLevel(riskLevel: 'low' | 'medium' | 'high' | 'critical'): Permission[] {
  return Object.values(PERMISSIONS).filter(p => p.risk_level === riskLevel);
}
