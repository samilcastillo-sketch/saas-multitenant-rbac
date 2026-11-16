/**
 * Authentication & Cryptographic Token Module (Native ES Modules)
 * Uses native node:crypto for high-security zero-dependency signing and hashing.
 */
import crypto from 'node:crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_hmac_signing_key_2026';
const TOKEN_TTL_MS = 3600 * 1000; // 1 hour

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, storedCombined) {
  const [salt, originalHash] = storedCombined.split(':');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(originalHash, 'hex'));
}

export function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const claims = {
    ...payload,
    exp: Date.now() + TOKEN_TTL_MS,
    iat: Date.now()
  };
  const body = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');

  return `${header}.${body}.${signature}`;
}

export function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
    return null;
  }

  try {
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (Date.now() > claims.exp) {
      return null; // Expired
    }
    return claims;
  } catch {
    return null;
  }
}
