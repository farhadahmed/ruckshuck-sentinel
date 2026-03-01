import crypto from 'crypto';

// In-memory stores (MVP; move to database + Redis for production)
const users = new Map<string, { id: string; email: string; passwordHash: string }>();
const sessions = new Map<
  string,
  { userId: string; email: string; createdAt: number; expiresAt: number }
>();

/**
 * Hash password using PBKDF2 (simple, no external deps for MVP)
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 100000;
  const hash = crypto
    .pbkdf2Sync(password, salt, iterations, 64, 'sha256')
    .toString('hex');
  return `${iterations}$${salt}$${hash}`;
}

/**
 * Verify password against stored hash
 */
export function verifyPassword(password: string, hash: string): boolean {
  const [iterStr, salt, storedHash] = hash.split('$');
  const iterations = parseInt(iterStr, 10);
  const computed = crypto
    .pbkdf2Sync(password, salt, iterations, 64, 'sha256')
    .toString('hex');
  return computed === storedHash;
}

/**
 * Create a new user
 */
export async function createUser(
  email: string,
  password: string
): Promise<{ id: string; email: string }> {
  const id = crypto.randomUUID();
  const passwordHash = hashPassword(password);
  users.set(id, { id, email, passwordHash });
  return { id, email };
}

/**
 * Find user by email
 */
export async function findUserByEmail(
  email: string
): Promise<{ id: string; email: string; passwordHash: string } | null> {
  for (const user of users.values()) {
    if (user.email === email) {
      return user;
    }
  }
  return null;
}

/**
 * Create a new session
 */
export function createSession(userId: string): {
  sessionId: string;
  expiresAt: number;
} {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const user = Array.from(users.values()).find((u) => u.id === userId);
  if (!user) {
    throw new Error('User not found');
  }

  const now = Date.now();
  const expiresAt = now + 60 * 60 * 1000; // 1 hour

  sessions.set(sessionId, {
    userId,
    email: user.email,
    createdAt: now,
    expiresAt,
  });

  return { sessionId, expiresAt };
}

/**
 * Get session and validate expiry
 */
export function getSession(sessionId: string): {
  id: string;
  email: string;
} | null {
  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }

  return { id: session.userId, email: session.email };
}

/**
 * Destroy a session (logout)
 */
export function destroySession(sessionId: string): void {
  sessions.delete(sessionId);
}
