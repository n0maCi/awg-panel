import { randomBytes } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import bcrypt from 'bcryptjs';

const COOKIE_NAME = 'awg_session';

interface Session {
  expiresAt: number;
}

interface Attempt {
  count: number;
  resetAt: number;
}

export class AuthService {
  private readonly sessions = new Map<string, Session>();
  private readonly attempts = new Map<string, Attempt>();

  constructor(
    private readonly passwordHash: string,
    private readonly ttlMs: number,
    private readonly secureCookie: boolean,
  ) {}

  middleware = (request: Request, response: Response, next: NextFunction): void => {
    const token = request.cookies?.[COOKIE_NAME] as string | undefined;
    const session = token ? this.sessions.get(token) : undefined;
    if (!session || session.expiresAt <= Date.now()) {
      if (token) this.sessions.delete(token);
      response.status(401).json({ error: 'Требуется авторизация' });
      return;
    }
    next();
  };

  isAuthenticated(request: Request): boolean {
    const token = request.cookies?.[COOKIE_NAME] as string | undefined;
    const session = token ? this.sessions.get(token) : undefined;
    return Boolean(session && session.expiresAt > Date.now());
  }

  async login(request: Request, response: Response, password: string): Promise<boolean> {
    const key = request.socket.remoteAddress || 'unknown';
    const now = Date.now();
    for (const [token, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(token);
    }
    const attempt = this.attempts.get(key);
    if (attempt && attempt.resetAt > now && attempt.count >= 5) {
      response.status(429).json({ error: 'Слишком много попыток. Повторите через 15 минут' });
      return false;
    }

    const normalizedHash = this.passwordHash.startsWith('$2y$')
      ? `$2b$${this.passwordHash.slice(4)}`
      : this.passwordHash;
    const valid = await bcrypt.compare(password, normalizedHash);
    if (!valid) {
      const current = attempt && attempt.resetAt > now ? attempt : { count: 0, resetAt: now + 15 * 60 * 1000 };
      current.count += 1;
      this.attempts.set(key, current);
      response.status(401).json({ error: 'Неверный пароль' });
      return false;
    }

    this.attempts.delete(key);
    const token = randomBytes(32).toString('base64url');
    this.sessions.set(token, { expiresAt: now + this.ttlMs });
    response.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      secure: this.secureCookie,
      sameSite: 'strict',
      path: '/',
      maxAge: this.ttlMs,
    });
    return true;
  }

  logout(request: Request, response: Response): void {
    const token = request.cookies?.[COOKIE_NAME] as string | undefined;
    if (token) this.sessions.delete(token);
    response.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: this.secureCookie,
      sameSite: 'strict',
      path: '/',
    });
  }
}
