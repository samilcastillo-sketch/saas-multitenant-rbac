/**
 * Multi-Tenant Data Store with strict isolation guarantees & Audit Logging.
 */
import crypto from 'node:crypto';

export class TenantDataStore {
  constructor() {
    this.tenants = new Map();       // tenantId -> { id, name, createdAt }
    this.users = new Map();         // userId -> { id, email, passwordHash, createdAt }
    this.memberships = new Map();   // `${tenantId}:${userId}` -> { tenantId, userId, role, joinedAt }
    this.resources = new Map();     // resourceId -> { id, tenantId, title, content, createdBy, createdAt }
    this.invitations = new Map();   // token -> { token, tenantId, email, role, expiresAt, used }
    this.auditLogs = [];            // [{ id, tenantId, userId, action, details, timestamp }]
  }

  // Tenant methods
  createTenant(name, ownerUserId) {
    const tenantId = `tenant_${crypto.randomUUID().slice(0, 8)}`;
    const tenant = { id: tenantId, name, createdAt: new Date().toISOString() };
    this.tenants.set(tenantId, tenant);

    // Make creator the OWNER
    this.setMembership(tenantId, ownerUserId, 'OWNER');
    this.logAudit(tenantId, ownerUserId, 'TENANT_CREATED', { name });
    return tenant;
  }

  getTenant(tenantId) {
    return this.tenants.get(tenantId) || null;
  }

  // User & Membership methods
  createUser(email, passwordHash) {
    const existing = [...this.users.values()].find(u => u.email.toLowerCase() === email.toLowerCase());
    if (existing) {
      throw new Error('User already exists with this email');
    }
    const userId = `usr_${crypto.randomUUID().slice(0, 8)}`;
    const user = { id: userId, email: email.toLowerCase(), passwordHash, createdAt: new Date().toISOString() };
    this.users.set(userId, user);
    return user;
  }

  getUserByEmail(email) {
    return [...this.users.values()].find(u => u.email.toLowerCase() === email.toLowerCase()) || null;
  }

  getUserById(userId) {
    return this.users.get(userId) || null;
  }

  setMembership(tenantId, userId, role) {
    const key = `${tenantId}:${userId}`;
    const membership = { tenantId, userId, role, joinedAt: new Date().toISOString() };
    this.memberships.set(key, membership);
    return membership;
  }

  getMembership(tenantId, userId) {
    return this.memberships.get(`${tenantId}:${userId}`) || null;
  }

  // Multi-Tenant Isolated Resource methods
  createResource(tenantId, userId, title, content) {
    const resourceId = `res_${crypto.randomUUID().slice(0, 8)}`;
    const resource = {
      id: resourceId,
      tenantId, // Strict tenant binding
      title,
      content,
      createdBy: userId,
      createdAt: new Date().toISOString()
    };
    this.resources.set(resourceId, resource);
    this.logAudit(tenantId, userId, 'RESOURCE_CREATED', { resourceId, title });
    return resource;
  }

  getResourcesByTenant(tenantId) {
    // Strictly isolate data: only return resources matching tenantId
    return [...this.resources.values()].filter(r => r.tenantId === tenantId);
  }

  getResource(tenantId, resourceId) {
    const resource = this.resources.get(resourceId);
    if (!resource || resource.tenantId !== tenantId) {
      return null; // Return null if resource belongs to another tenant (Tenant Isolation)
    }
    return resource;
  }

  deleteResource(tenantId, userId, resourceId) {
    const resource = this.getResource(tenantId, resourceId);
    if (!resource) return false;
    this.resources.delete(resourceId);
    this.logAudit(tenantId, userId, 'RESOURCE_DELETED', { resourceId, title: resource.title });
    return true;
  }

  // Single-use Invitation system
  createInvitation(tenantId, inviterUserId, email, role) {
    const token = crypto.randomBytes(24).toString('hex');
    const invitation = {
      token,
      tenantId,
      email: email.toLowerCase(),
      role,
      expiresAt: Date.now() + (24 * 3600 * 1000), // 24 hours
      used: false
    };
    this.invitations.set(token, invitation);
    this.logAudit(tenantId, inviterUserId, 'INVITATION_ISSUED', { email, role });
    return invitation;
  }

  acceptInvitation(token, userId) {
    const invitation = this.invitations.get(token);
    if (!invitation) throw new Error('Invalid invitation token');
    if (invitation.used) throw new Error('Invitation token already used');
    if (Date.now() > invitation.expiresAt) throw new Error('Invitation token expired');

    invitation.used = true;
    this.setMembership(invitation.tenantId, userId, invitation.role);
    this.logAudit(invitation.tenantId, userId, 'INVITATION_ACCEPTED', { role: invitation.role });
    return invitation;
  }

  // Audit Logs
  logAudit(tenantId, userId, action, details) {
    this.auditLogs.push({
      id: `aud_${crypto.randomUUID().slice(0, 8)}`,
      tenantId,
      userId,
      action,
      details,
      timestamp: new Date().toISOString()
    });
  }

  getAuditLogs(tenantId) {
    return this.auditLogs.filter(log => log.tenantId === tenantId);
  }
}
