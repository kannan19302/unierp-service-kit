/**
 * @unerp/service-kit — the contract between the UniERP core gateway and
 * out-of-process extension services (industry apps in their own repos).
 *
 * Core signs a short-lived tenant-context token per proxied request; the
 * service verifies it and derives all tenant/user context from it. Services
 * never trust raw headers — only the signed token.
 */
import { createHmac, timingSafeEqual } from 'crypto';

/** Current contract version exposed by core and extension services. */
export const EXT_API_VERSION = 1;
/** Oldest extension contract still accepted by this core release. */
export const MIN_SUPPORTED_EXT_API_VERSION = 1;

/** True when an extension's declared contract is within the supported range. */
export function isSupportedExtApiVersion(version: number): boolean {
  return Number.isInteger(version) && version >= MIN_SUPPORTED_EXT_API_VERSION && version <= EXT_API_VERSION;
}

/** Header carrying the signed tenant-context token on proxied requests. */
export const TENANT_TOKEN_HEADER = 'x-unierp-tenant-token';
/** Correlation id propagated from the gateway. */
export const REQUEST_ID_HEADER = 'x-request-id';
/** Signature + timestamp headers on core→service event webhooks. */
export const WEBHOOK_SIGNATURE_HEADER = 'x-unierp-signature';
export const WEBHOOK_TIMESTAMP_HEADER = 'x-unierp-timestamp';

/** Default TTL for tenant-context tokens (seconds). */
export const TENANT_TOKEN_TTL_SECONDS = 60;

/** A core domain event a bundle subscribes to (delivered as a signed webhook). */
export interface ManifestEventSubscription {
  /** Event name, e.g. "invoice.paid" or "crm.contact.created". Supports trailing ".*". */
  event: string;
  /** Path on the service the event is POSTed to, e.g. "/events". */
  deliverTo: string;
}

/** `service` section of an AppManifest (runtime: 'declarative+service'). */
export interface ManifestService {
  /** Route prefix under /api/v1/ext/<prefix>/* on core. Defaults to the app slug. */
  routePrefix?: string;
  /** Env var core reads to find the service base URL (overrides defaultBaseUrl). */
  baseUrlEnv?: string;
  /** Fallback base URL, e.g. http://fieldservice-svc:4103 for docker-compose. */
  defaultBaseUrl?: string;
  /** Health check path on the service, e.g. /svc/health. */
  healthcheck: string;
  /** Scopes core embeds in the tenant-context token. */
  scopes?: string[];
  /** Per-request proxy timeout (ms). Default 15000. */
  timeoutMs?: number;
  /** Core domain events this app receives as signed webhooks. */
  events?: ManifestEventSubscription[];
}

/** Claims inside the tenant-context token. */
export interface TenantContextClaims {
  tenantId: string;
  userId: string;
  email?: string;
  roles: string[];
  appSlug: string;
  scopes: string[];
  iat: number;
  exp: number;
}

/** Standard error envelope the gateway and services both emit. */
export interface ExtErrorEnvelope {
  statusCode: number;
  error: string;
  message: string;
  app?: string;
  requestId?: string;
}

/** Standard health response shape (GET <healthcheck>). */
export interface ExtHealthResponse {
  status: 'ok';
  app: string;
  version?: string;
  apiVersion: number;
  time: string;
}

export function buildHealthResponse(app: string, version?: string): ExtHealthResponse {
  return { status: 'ok', app, version, apiVersion: EXT_API_VERSION, time: new Date().toISOString() };
}

// ─── Minimal HS256 JWT (no dependencies) ───

const b64url = (buf: Buffer) =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function hs256(input: string, secret: string): Buffer {
  return createHmac('sha256', secret).update(input).digest();
}

/** Constant-time compare of two hex/base64url strings of the same intent. */
function safeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Sign a tenant-context token (HS256). Used by core's gateway. */
export function signTenantToken(
  claims: Omit<TenantContextClaims, 'iat' | 'exp'>,
  secret: string,
  ttlSeconds: number = TENANT_TOKEN_TTL_SECONDS,
): string {
  if (!secret) throw new Error('signTenantToken: secret is required');
  const now = Math.floor(Date.now() / 1000);
  const full: TenantContextClaims = { ...claims, iat: now, exp: now + ttlSeconds };
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = b64url(Buffer.from(JSON.stringify(full)));
  const sig = b64url(hs256(`${header}.${payload}`, secret));
  return `${header}.${payload}.${sig}`;
}

/**
 * Decode a token's claims WITHOUT verifying the signature. Only for selecting
 * which per-app secret to verify with — never trust the result before calling
 * verifyTenantToken.
 */
export function decodeTokenUnverified(token: string): Partial<TenantContextClaims> | null {
  const parts = (token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(fromB64url(parts[1]!).toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Verify a tenant-context token. Throws on any problem (bad signature, expired,
 * wrong app). Returns the claims on success.
 */
export function verifyTenantToken(
  token: string,
  secret: string,
  opts: { expectedAppSlug?: string } = {},
): TenantContextClaims {
  if (!secret) throw new Error('verifyTenantToken: secret is required');
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed tenant token');
  const [header, payload, sig] = parts as [string, string, string];
  const expected = hs256(`${header}.${payload}`, secret);
  const actual = fromB64url(sig);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error('Invalid tenant token signature');
  }
  let claims: TenantContextClaims;
  try {
    claims = JSON.parse(fromB64url(payload).toString('utf8'));
  } catch {
    throw new Error('Malformed tenant token payload');
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp < now) throw new Error('Tenant token expired');
  if (!claims.tenantId) throw new Error('Tenant token missing tenantId');
  if (opts.expectedAppSlug && claims.appSlug !== opts.expectedAppSlug) {
    throw new Error(`Tenant token issued for app "${claims.appSlug}", not "${opts.expectedAppSlug}"`);
  }
  return claims;
}

/**
 * Minimal structural types for an Express-like request/response, kept local
 * so service-kit has zero runtime dependency on the `express` package while
 * still type-checking against real Express objects (structurally compatible).
 */
export interface MinimalRequest {
  path: string;
  headers: Record<string, string | string[] | undefined>;
  tenantContext?: TenantContextClaims;
}
export interface MinimalResponse {
  status(code: number): MinimalResponse;
  json(body: unknown): void;
}
export type NextFn = () => void;

/**
 * Express-style middleware factory for extension services: verifies the token
 * and attaches `req.tenantContext`. Skips paths in `publicPaths` (health checks).
 */
export function tenantContextMiddleware(options: {
  secret: string;
  appSlug: string;
  publicPaths?: string[];
}) {
  const publicPaths = new Set(options.publicPaths || []);
  return (req: MinimalRequest, res: MinimalResponse, next: NextFn) => {
    if (publicPaths.has(req.path)) return next();
    const token = req.headers?.[TENANT_TOKEN_HEADER];
    try {
      req.tenantContext = verifyTenantToken(String(token || ''), options.secret, {
        expectedAppSlug: options.appSlug,
      });
      return next();
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Invalid tenant token';
      res.status(401).json({
        statusCode: 401,
        error: 'Unauthorized',
        message,
        app: options.appSlug,
      } satisfies ExtErrorEnvelope);
    }
  };
}

// ─── RBAC (#1): pure checks + a Nest-compatible guard factory ───

export function hasRole(claims: TenantContextClaims | undefined, role: string): boolean {
  return !!claims && Array.isArray(claims.roles) && claims.roles.includes(role);
}
export function hasScope(claims: TenantContextClaims | undefined, scope: string): boolean {
  return !!claims && Array.isArray(claims.scopes) && claims.scopes.includes(scope);
}

/** Error carrying an HTTP status so services can map it to a 403 response. */
export class ExtForbiddenError extends Error {
  statusCode = 403;
  constructor(message: string) {
    super(message);
    this.name = 'ExtForbiddenError';
  }
}

/**
 * Assert the token carries every required scope (or, if `mode: "any"`, at least
 * one). Throws ExtForbiddenError otherwise.
 */
export function assertScopes(
  claims: TenantContextClaims | undefined,
  required: string[],
  mode: 'all' | 'any' = 'all',
): void {
  if (!claims) throw new ExtForbiddenError('No tenant context');
  if (required.length === 0) return;
  const have = new Set(claims.scopes || []);
  const ok = mode === 'any' ? required.some((s) => have.has(s)) : required.every((s) => have.has(s));
  if (!ok) {
    throw new ExtForbiddenError(
      `Missing required scope(s): ${required.join(mode === 'any' ? ' | ' : ', ')}`,
    );
  }
}

/**
 * Structural stand-in for Nest's ExecutionContext — service-kit has no
 * @nestjs/* dependency, but this shape matches it closely enough that a real
 * ExecutionContext satisfies it at the call site.
 */
export interface MinimalExecutionContext {
  switchToHttp(): { getRequest(): MinimalRequest };
}

/**
 * A Nest-compatible guard factory (implemented without importing @nestjs/*).
 * Usage in a service controller:  @UseGuards(RequireScopes('healthcare:write'))
 */
export function RequireScopes(...scopes: string[]) {
  return class ScopeGuard {
    canActivate(context: MinimalExecutionContext): boolean {
      const req = context.switchToHttp().getRequest();
      assertScopes(req.tenantContext, scopes, 'all');
      return true;
    }
  };
}
export function RequireAnyScope(...scopes: string[]) {
  return class AnyScopeGuard {
    canActivate(context: MinimalExecutionContext): boolean {
      const req = context.switchToHttp().getRequest();
      assertScopes(req.tenantContext, scopes, 'any');
      return true;
    }
  };
}

// ─── Webhooks (#6): sign/verify core→service event deliveries ───

/** Sign a webhook body. Returns the value for WEBHOOK_SIGNATURE_HEADER. */
export function signWebhook(rawBody: string, secret: string, timestamp: number): string {
  return 'v1=' + hs256(`${timestamp}.${rawBody}`, secret).toString('hex');
}

/**
 * Verify a webhook signature within `toleranceSec` of the timestamp. Throws on
 * mismatch or stale timestamp (replay protection).
 */
export function verifyWebhook(
  rawBody: string,
  signatureHeader: string,
  timestampHeader: string | number,
  secret: string,
  toleranceSec = 300,
): void {
  const ts = Number(timestampHeader);
  if (!ts || Number.isNaN(ts)) throw new Error('Missing/invalid webhook timestamp');
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSec) {
    throw new Error('Webhook timestamp outside tolerance (possible replay)');
  }
  const expected = signWebhook(rawBody, secret, ts);
  if (!signatureHeader || !safeEqualStr(signatureHeader, expected)) {
    throw new Error('Invalid webhook signature');
  }
}

// ─── Versioning (#7): semver compare for minCoreVersion checks ───

export function compareSemver(a: string, b: string): number {
  const pa = a.split('-')[0]!.split('.').map(Number);
  const pb = b.split('-')[0]!.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}
/** True when `coreVersion` >= `minCoreVersion`. */
export function satisfiesMinCoreVersion(coreVersion: string, minCoreVersion?: string): boolean {
  if (!minCoreVersion) return true;
  return compareSemver(coreVersion, minCoreVersion) >= 0;
}

// ─── Core client (#9, #10): read/write provisioned records via ext-callback ───

export interface CoreRecordFilter {
  /** Equality filters on record data fields, e.g. { patient_mrn: "MRN1" }. */
  where?: Record<string, unknown>;
  limit?: number;
}

/**
 * Typed client for the core ext-callback API. Services construct it per request
 * with the raw tenant token they received, and core authorizes by that token
 * (scoped to the app's own schemas).
 */
export class CoreClient {
  constructor(
    private readonly opts: { coreApiUrl: string; token: string },
  ) {}

  private base(): string {
    return `${this.opts.coreApiUrl.replace(/\/+$/, '')}/api/v1/ext-callback`;
  }
  private headers(): Record<string, string> {
    return { 'content-type': 'application/json', [TENANT_TOKEN_HEADER]: this.opts.token };
  }

  /** Read all/filtered records for one provisioned schema slug. */
  async records(schemaSlug: string, filter?: CoreRecordFilter): Promise<Record<string, unknown>[]> {
    const qs = new URLSearchParams();
    if (filter?.where) qs.set('where', JSON.stringify(filter.where));
    if (filter?.limit) qs.set('limit', String(filter.limit));
    const q = qs.toString();
    const res = await fetch(`${this.base()}/records/${schemaSlug}${q ? `?${q}` : ''}`, {
      headers: this.headers(),
    });
    if (!res.ok) return [];
    const rows = await res.json().catch(() => []);
    return Array.isArray(rows) ? rows : [];
  }

  /** Fetch several schemas at once (one round trip). Returns a slug→rows map. */
  async recordsBatch(schemaSlugs: string[]): Promise<Record<string, Record<string, unknown>[]>> {
    const res = await fetch(`${this.base()}/records:batch`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ slugs: schemaSlugs }),
    });
    if (!res.ok) return Object.fromEntries(schemaSlugs.map((s) => [s, []]));
    return (await res.json().catch(() => ({}))) as Record<string, Record<string, unknown>[]>;
  }

  /** Create a record in a provisioned schema (requires a *:write* scope in the token). */
  async createRecord(schemaSlug: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.base()}/records/${schemaSlug}`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ data }),
    });
    if (!res.ok) throw new Error(`createRecord ${schemaSlug} failed: ${res.status}`);
    return (await res.json()) as Record<string, unknown>;
  }
}
