import cookiePlugin from '@fastify/cookie';
import jwtPlugin from '@fastify/jwt';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { authRoutes } from '../routes/auth.js';

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });

  await app.register(cookiePlugin as any);
  await app.register(jwtPlugin as any, {
    secret: 'test-secret-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    cookie: { cookieName: 'access_Token', signed: false },
  });

  app.decorate('prisma', {
    user: { findUnique: vi.fn(), create: vi.fn(), update: vi.fn() },
    userIdentity: { findUnique: vi.fn(), create: vi.fn() },
    refreshToken: { create: vi.fn() },
  } as any);

  app.decorate('redis', {
    set: vi.fn(),
    getdel: vi.fn(),
  } as any);

  app.decorate('authenticate', async () => {});

  await app.register(authRoutes, { prefix: '/auth' });
  await app.ready();
  return app;
}

describe('GET /auth/github/callback — Zod validation', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildTestApp();
  });

  afterEach(async () => {
    await app.close();
  });

  it('400 — missing code rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?state=somestate',
      headers: { Cookie: 'oauth_state=somestate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — empty code rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=&state=somestate',
      headers: { Cookie: 'oauth_state=somestate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — missing state rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=validcode',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — empty state rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=validcode&state=',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — valid code and state but no cookie rejects with state error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=validcode&state=somestate',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid or missing OAuth state — possible CSRF attack');
  });

  it('400 — valid code and state but mismatched cookie rejects with state error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=validcode&state=somestate',
      headers: { Cookie: 'oauth_state=differentstate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid or missing OAuth state — possible CSRF attack');
  });

  it('validation error response includes field-level details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?state=somestate',
      headers: { Cookie: 'oauth_state=somestate' },
    });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.details).toBeDefined();
    expect(body.details.fieldErrors).toHaveProperty('code');
  });
});

describe('GET /auth/google/callback — Zod validation', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildTestApp();
  });

  afterEach(async () => {
    await app.close();
  });

  it('400 — missing code rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?state=somestate',
      headers: { Cookie: 'oauth_state=somestate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — empty code rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=&state=somestate',
      headers: { Cookie: 'oauth_state=somestate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — missing state rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=validcode',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — empty state rejects with validation error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=validcode&state=',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
  });

  it('400 — valid code and state but no cookie rejects with state error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=validcode&state=somestate',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid or missing OAuth state — possible CSRF attack');
  });

  it('400 — valid code and state but mismatched cookie rejects with state error', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=validcode&state=somestate',
      headers: { Cookie: 'oauth_state=differentstate' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid or missing OAuth state — possible CSRF attack');
  });

  it('validation error response includes field-level details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=validcode',
    });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.details).toBeDefined();
    expect(body.details.fieldErrors).toHaveProperty('state');
  });
});
