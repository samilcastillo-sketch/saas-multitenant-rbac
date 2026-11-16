/**
 * Automated Test Suite for SaaS Multi-Tenant & RBAC Platform
 * Executed via native `node --test` runner.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, generateToken, verifyToken } from '../src/auth.js';
import { Roles, Permissions, hasPermission } from '../src/rbac.js';
import { TenantDataStore } from '../src/store.js';

test('Security: Password hashing with scrypt and salt verification', () => {
  const plain = 'P@sswordSecure2026!';
  const hashed = hashPassword(plain);
  assert.notEqual(plain, hashed);
  assert.equal(verifyPassword(plain, hashed), true);
  assert.equal(verifyPassword('WrongPassword', hashed), false);
});

test('Security: JWT Token generation, payload validation, and expiration check', () => {
  const payload = { userId: 'usr_test1', email: 'test@example.com' };
  const token = generateToken(payload);
  const decoded = verifyToken(token);

  assert.equal(decoded.userId, 'usr_test1');
  assert.equal(decoded.email, 'test@example.com');
  assert.ok(decoded.exp > Date.now());

  // Tampered token fails
  const tampered = token.slice(0, -4) + 'abcd';
  assert.equal(verifyToken(tampered), null);
});

test('RBAC: Matrix permissions check across hierarchy', () => {
  // OWNER can delete tenant
  assert.equal(hasPermission(Roles.OWNER, Permissions.TENANT_DELETE), true);
  // ADMIN cannot delete tenant, but can invite users
  assert.equal(hasPermission(Roles.ADMIN, Permissions.TENANT_DELETE), false);
  assert.equal(hasPermission(Roles.ADMIN, Permissions.USER_INVITE), true);
  // MEMBER can create resources, but not invite users
  assert.equal(hasPermission(Roles.MEMBER, Permissions.RESOURCE_CREATE), true);
  assert.equal(hasPermission(Roles.MEMBER, Permissions.USER_INVITE), false);
  // VIEWER can only read
  assert.equal(hasPermission(Roles.VIEWER, Permissions.RESOURCE_READ), true);
  assert.equal(hasPermission(Roles.VIEWER, Permissions.RESOURCE_CREATE), false);
});

test('Multi-Tenancy: Strict Data Isolation between Tenants', () => {
  const store = new TenantDataStore();

  const userA = store.createUser('alice@company-a.com', hashPassword('pass123'));
  const userB = store.createUser('bob@company-b.com', hashPassword('pass123'));

  const tenantA = store.createTenant('Acme Corp', userA.id);
  const tenantB = store.createTenant('Beta Global', userB.id);

  // Alice creates a private contract in Tenant A
  const resA = store.createResource(tenantA.id, userA.id, 'Financial Report 2026', 'Strictly confidential');
  
  // Bob creates a document in Tenant B
  store.createResource(tenantB.id, userB.id, 'Product Roadmap', 'Secret features');

  // Verify Tenant A only contains Tenant A resources
  const tenantAResources = store.getResourcesByTenant(tenantA.id);
  assert.equal(tenantAResources.length, 1);
  assert.equal(tenantAResources[0].title, 'Financial Report 2026');

  // Verify cross-tenant access to resource ID returns null
  const leakCheck = store.getResource(tenantB.id, resA.id);
  assert.equal(leakCheck, null, 'Tenant B must NOT access Tenant A resources');
});

test('Invitations: Single-use token enforcement and role assignment', () => {
  const store = new TenantDataStore();
  const owner = store.createUser('ceo@startup.io', hashPassword('pass123'));
  const newMember = store.createUser('dev@startup.io', hashPassword('pass123'));
  const tenant = store.createTenant('Startup Inc', owner.id);

  const invite = store.createInvitation(tenant.id, owner.id, 'dev@startup.io', Roles.MEMBER);
  assert.equal(invite.used, false);

  // Accept invitation
  store.acceptInvitation(invite.token, newMember.id);

  // Verify membership updated
  const membership = store.getMembership(tenant.id, newMember.id);
  assert.equal(membership.role, Roles.MEMBER);

  // Attempting to reuse the token must fail
  assert.throws(() => {
    store.acceptInvitation(invite.token, newMember.id);
  }, /already used/);
});
