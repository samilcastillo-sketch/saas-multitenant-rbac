/**
 * Role-Based Access Control (RBAC) Definition Matrix
 */

export const Roles = {
  OWNER: 'OWNER',
  ADMIN: 'ADMIN',
  MEMBER: 'MEMBER',
  VIEWER: 'VIEWER'
};

export const Permissions = {
  TENANT_DELETE: 'tenant:delete',
  TENANT_UPDATE: 'tenant:update',
  USER_INVITE: 'user:invite',
  USER_REMOVE: 'user:remove',
  RESOURCE_CREATE: 'resource:create',
  RESOURCE_READ: 'resource:read',
  RESOURCE_UPDATE: 'resource:update',
  RESOURCE_DELETE: 'resource:delete',
  AUDIT_READ: 'audit:read'
};

// Hierarchy and Permission assignments
const ROLE_PERMISSIONS = {
  [Roles.OWNER]: [
    Permissions.TENANT_DELETE,
    Permissions.TENANT_UPDATE,
    Permissions.USER_INVITE,
    Permissions.USER_REMOVE,
    Permissions.RESOURCE_CREATE,
    Permissions.RESOURCE_READ,
    Permissions.RESOURCE_UPDATE,
    Permissions.RESOURCE_DELETE,
    Permissions.AUDIT_READ
  ],
  [Roles.ADMIN]: [
    Permissions.TENANT_UPDATE,
    Permissions.USER_INVITE,
    Permissions.USER_REMOVE,
    Permissions.RESOURCE_CREATE,
    Permissions.RESOURCE_READ,
    Permissions.RESOURCE_UPDATE,
    Permissions.RESOURCE_DELETE,
    Permissions.AUDIT_READ
  ],
  [Roles.MEMBER]: [
    Permissions.RESOURCE_CREATE,
    Permissions.RESOURCE_READ,
    Permissions.RESOURCE_UPDATE
  ],
  [Roles.VIEWER]: [
    Permissions.RESOURCE_READ
  ]
};

export function hasPermission(userRole, requiredPermission) {
  const allowed = ROLE_PERMISSIONS[userRole] || [];
  return allowed.includes(requiredPermission);
}
