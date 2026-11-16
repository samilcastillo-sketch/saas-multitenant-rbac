/**
 * Production-ready SaaS Multi-Tenant RBAC HTTP Server
 * Written in native Node.js ES Modules (Zero third-party dependencies)
 */
import http from 'node:http';
import { hashPassword, verifyPassword, generateToken, verifyToken } from './auth.js';
import { Roles, Permissions, hasPermission } from './rbac.js';
import { TenantDataStore } from './store.js';

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

export function createServer(store = new TenantDataStore()) {
  const server = http.createServer(async (req, res) => {
    // Utility for JSON response
    const sendJson = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data, null, 2));
    };

    // Parse Body
    let body = {};
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      try {
        const buffers = [];
        for await (const chunk of req) buffers.push(chunk);
        const raw = Buffer.concat(buffers).toString();
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return sendJson(400, { error: 'Invalid JSON body' });
      }
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    const method = req.method;

    // Extract Bearer Token
    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const authUser = token ? verifyToken(token) : null;

    // Health Check
    if (method === 'GET' && path === '/health') {
      return sendJson(200, { status: 'healthy', service: 'saas-multitenant-rbac', version: '1.0.0' });
    }

    // --- PUBLIC AUTH ROUTES ---
    if (method === 'POST' && path === '/api/v1/auth/register') {
      const { email, password } = body;
      if (!email || !password || password.length < 6) {
        return sendJson(400, { error: 'Email and password (min 6 chars) required' });
      }
      try {
        const passwordHash = hashPassword(password);
        const user = store.createUser(email, passwordHash);
        const jwt = generateToken({ userId: user.id, email: user.email });
        return sendJson(201, { user: { id: user.id, email: user.email }, token: jwt });
      } catch (err) {
        return sendJson(409, { error: err.message });
      }
    }

    if (method === 'POST' && path === '/api/v1/auth/login') {
      const { email, password } = body;
      const user = store.getUserByEmail(email);
      if (!user || !verifyPassword(password, user.passwordHash)) {
        return sendJson(401, { error: 'Invalid email or password' });
      }
      const jwt = generateToken({ userId: user.id, email: user.email });
      return sendJson(200, { user: { id: user.id, email: user.email }, token: jwt });
    }

    // Require Auth for all downstream routes
    if (!authUser) {
      return sendJson(401, { error: 'Unauthorized: Valid Bearer token required' });
    }

    // --- TENANT CREATION ---
    if (method === 'POST' && path === '/api/v1/tenants') {
      const { name } = body;
      if (!name) return sendJson(400, { error: 'Tenant name is required' });
      const tenant = store.createTenant(name, authUser.userId);
      return sendJson(201, { tenant, role: Roles.OWNER });
    }

    // --- TENANT-SCOPED OPERATIONS ---
    // Extract tenant ID from header or path: /api/v1/tenants/:tenantId/...
    const tenantMatch = path.match(/^\/api\/v1\/tenants\/([^/]+)(\/.*)?$/);
    const tenantId = req.headers['x-tenant-id'] || (tenantMatch ? tenantMatch[1] : null);

    if (!tenantId) {
      return sendJson(400, { error: 'Tenant ID required via X-Tenant-ID header or path parameter' });
    }

    const tenant = store.getTenant(tenantId);
    if (!tenant) {
      return sendJson(404, { error: 'Tenant organization not found' });
    }

    // Verify User Membership in this Tenant
    const membership = store.getMembership(tenantId, authUser.userId);
    if (!membership) {
      return sendJson(403, { error: 'Forbidden: You are not a member of this tenant' });
    }

    const subPath = tenantMatch?.[2] || '';

    // 1. Create Resource (requires RESOURCE_CREATE)
    if (method === 'POST' && subPath === '/resources') {
      if (!hasPermission(membership.role, Permissions.RESOURCE_CREATE)) {
        return sendJson(403, { error: `Forbidden: Role ${membership.role} lacks permission ${Permissions.RESOURCE_CREATE}` });
      }
      const { title, content } = body;
      if (!title) return sendJson(400, { error: 'Title is required' });
      const resource = store.createResource(tenantId, authUser.userId, title, content || '');
      return sendJson(201, { resource });
    }

    // 2. List Resources (requires RESOURCE_READ) - Strictly isolated
    if (method === 'GET' && subPath === '/resources') {
      if (!hasPermission(membership.role, Permissions.RESOURCE_READ)) {
        return sendJson(403, { error: `Forbidden: Role ${membership.role} lacks permission ${Permissions.RESOURCE_READ}` });
      }
      const resources = store.getResourcesByTenant(tenantId);
      return sendJson(200, { tenantId, resources });
    }

    // 3. Delete Resource (requires RESOURCE_DELETE)
    const resDeleteMatch = subPath.match(/^\/resources\/([^/]+)$/);
    if (method === 'DELETE' && resDeleteMatch) {
      if (!hasPermission(membership.role, Permissions.RESOURCE_DELETE)) {
        return sendJson(403, { error: `Forbidden: Role ${membership.role} lacks permission ${Permissions.RESOURCE_DELETE}` });
      }
      const resourceId = resDeleteMatch[1];
      const deleted = store.deleteResource(tenantId, authUser.userId, resourceId);
      if (!deleted) return sendJson(404, { error: 'Resource not found in this tenant' });
      return sendJson(200, { message: 'Resource deleted successfully' });
    }

    // 4. Invite User (requires USER_INVITE)
    if (method === 'POST' && subPath === '/invitations') {
      if (!hasPermission(membership.role, Permissions.USER_INVITE)) {
        return sendJson(403, { error: `Forbidden: Role ${membership.role} lacks permission ${Permissions.USER_INVITE}` });
      }
      const { email, role } = body;
      if (!email || !Object.values(Roles).includes(role)) {
        return sendJson(400, { error: `Valid email and role (${Object.values(Roles).join(', ')}) required` });
      }
      const invitation = store.createInvitation(tenantId, authUser.userId, email, role);
      return sendJson(201, { invitation });
    }

    // 5. Accept Invitation
    if (method === 'POST' && subPath === '/invitations/accept') {
      const { token: inviteToken } = body;
      try {
        const accepted = store.acceptInvitation(inviteToken, authUser.userId);
        return sendJson(200, { message: 'Invitation accepted', membership: { tenantId, role: accepted.role } });
      } catch (err) {
        return sendJson(400, { error: err.message });
      }
    }

    // 6. View Audit Logs (requires AUDIT_READ)
    if (method === 'GET' && subPath === '/audit-logs') {
      if (!hasPermission(membership.role, Permissions.AUDIT_READ)) {
        return sendJson(403, { error: `Forbidden: Role ${membership.role} lacks permission ${Permissions.AUDIT_READ}` });
      }
      const logs = store.getAuditLogs(tenantId);
      return sendJson(200, { tenantId, auditLogs: logs });
    }

    return sendJson(404, { error: 'Route not found' });
  });

  return server;
}

if (process.argv[1]?.endsWith('server.js')) {
  const app = createServer();
  app.listen(PORT, HOST, () => {
    console.log(`[SaaS Multi-Tenant RBAC] Listening on http://${HOST}:${PORT}`);
  });
}
