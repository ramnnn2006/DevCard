/**
 * Validation tests for the OAuth callback endpoints.
 *
 * /auth/github/callback and /auth/google/callback now run their query
 * parameters through a Zod schema before touching the state cookie or
 * exchanging the code with the provider. A missing or empty `code` should be
 * rejected with a 400 and a validation payload, well before any token
 * exchange happens.
 */

import cookiePlugin from '@fastify/cookie';
import jwtPlugin from '@fastify/jwt';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { authRoutes } from '../routes/auth.js';

const TEST_JWT_SECRET = 'test-secret-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; // ≥ 32 chars

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(cookiePlugin as any);
  await app.register(jwtPlugin as any, { secret: TEST_JWT_SECRET });
  app.decorate('prisma', {
    user: { findUnique: vi.fn().mockResolvedValue(null) },
  } as any);
  // /auth/me registers with preHandler: [app.authenticate], so the decorator
  // has to exist at registration time even though these tests never hit it.
  app.decorate('authenticate', async () => {});
  await app.register(authRoutes, { prefix: '/auth' });
  await app.ready();
  return app;
}

let app: FastifyInstance;
const mockFetch = vi.fn();

beforeEach(async () => {
  vi.clearAllMocks();
  // If validation ever lets a request through, this surfaces it: the test
  // asserts fetch was never called.
  (globalThis as any).fetch = mockFetch;
  app = await buildApp();
});

afterEach(async () => {
  await app.close();
});

describe('GET /auth/github/callback — query validation', () => {
  it('rejects a request with no code', async () => {
    const res = await app.inject({ method: 'GET', url: '/auth/github/callback' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('rejects an empty code', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=&state=abc',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('passes validation and reaches the state check when code is present', async () => {
    // No oauth_state cookie is set, so a valid code falls through to the CSRF
    // state check rather than the validation error.
    const res = await app.inject({
      method: 'GET',
      url: '/auth/github/callback?code=valid-code&state=abc',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toContain('OAuth state');
  });
});

describe('GET /auth/google/callback — query validation', () => {
  it('rejects a request with no code', async () => {
    const res = await app.inject({ method: 'GET', url: '/auth/google/callback' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('rejects an empty code', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=&state=abc',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('Invalid callback parameters');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('passes validation and reaches the state check when code is present', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/auth/google/callback?code=valid-code&state=abc',
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toContain('OAuth state');
  });
});
