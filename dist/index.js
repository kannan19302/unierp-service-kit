"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CoreClient = exports.ExtForbiddenError = exports.TENANT_TOKEN_TTL_SECONDS = exports.WEBHOOK_TIMESTAMP_HEADER = exports.WEBHOOK_SIGNATURE_HEADER = exports.REQUEST_ID_HEADER = exports.TENANT_TOKEN_HEADER = exports.MIN_SUPPORTED_EXT_API_VERSION = exports.EXT_API_VERSION = void 0;
exports.isSupportedExtApiVersion = isSupportedExtApiVersion;
exports.buildHealthResponse = buildHealthResponse;
exports.signTenantToken = signTenantToken;
exports.decodeTokenUnverified = decodeTokenUnverified;
exports.verifyTenantToken = verifyTenantToken;
exports.tenantContextMiddleware = tenantContextMiddleware;
exports.hasRole = hasRole;
exports.hasScope = hasScope;
exports.assertScopes = assertScopes;
exports.RequireScopes = RequireScopes;
exports.RequireAnyScope = RequireAnyScope;
exports.signWebhook = signWebhook;
exports.verifyWebhook = verifyWebhook;
exports.compareSemver = compareSemver;
exports.satisfiesMinCoreVersion = satisfiesMinCoreVersion;
/**
 * @unerp/service-kit — the contract between the UniERP core gateway and
 * out-of-process extension services (industry apps in their own repos).
 *
 * Core signs a short-lived tenant-context token per proxied request; the
 * service verifies it and derives all tenant/user context from it. Services
 * never trust raw headers — only the signed token.
 */
const crypto_1 = require("crypto");
/** Current contract version exposed by core and extension services. */
exports.EXT_API_VERSION = 1;
/** Oldest extension contract still accepted by this core release. */
exports.MIN_SUPPORTED_EXT_API_VERSION = 1;
/** True when an extension's declared contract is within the supported range. */
function isSupportedExtApiVersion(version) {
    return Number.isInteger(version) && version >= exports.MIN_SUPPORTED_EXT_API_VERSION && version <= exports.EXT_API_VERSION;
}
/** Header carrying the signed tenant-context token on proxied requests. */
exports.TENANT_TOKEN_HEADER = 'x-unierp-tenant-token';
/** Correlation id propagated from the gateway. */
exports.REQUEST_ID_HEADER = 'x-request-id';
/** Signature + timestamp headers on core→service event webhooks. */
exports.WEBHOOK_SIGNATURE_HEADER = 'x-unierp-signature';
exports.WEBHOOK_TIMESTAMP_HEADER = 'x-unierp-timestamp';
/** Default TTL for tenant-context tokens (seconds). */
exports.TENANT_TOKEN_TTL_SECONDS = 60;
function buildHealthResponse(app, version) {
    return { status: 'ok', app, version, apiVersion: exports.EXT_API_VERSION, time: new Date().toISOString() };
}
// ─── Minimal HS256 JWT (no dependencies) ───
const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
function hs256(input, secret) {
    return (0, crypto_1.createHmac)('sha256', secret).update(input).digest();
}
/** Constant-time compare of two hex/base64url strings of the same intent. */
function safeEqualStr(a, b) {
    const ab = Buffer.from(a);
    const bb = Buffer.from(b);
    return ab.length === bb.length && (0, crypto_1.timingSafeEqual)(ab, bb);
}
/** Sign a tenant-context token (HS256). Used by core's gateway. */
function signTenantToken(claims, secret, ttlSeconds = exports.TENANT_TOKEN_TTL_SECONDS) {
    if (!secret)
        throw new Error('signTenantToken: secret is required');
    const now = Math.floor(Date.now() / 1000);
    const full = { ...claims, iat: now, exp: now + ttlSeconds };
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
function decodeTokenUnverified(token) {
    const parts = (token || '').split('.');
    if (parts.length !== 3)
        return null;
    try {
        return JSON.parse(fromB64url(parts[1]).toString('utf8'));
    }
    catch {
        return null;
    }
}
/**
 * Verify a tenant-context token. Throws on any problem (bad signature, expired,
 * wrong app). Returns the claims on success.
 */
function verifyTenantToken(token, secret, opts = {}) {
    if (!secret)
        throw new Error('verifyTenantToken: secret is required');
    const parts = (token || '').split('.');
    if (parts.length !== 3)
        throw new Error('Malformed tenant token');
    const [header, payload, sig] = parts;
    const expected = hs256(`${header}.${payload}`, secret);
    const actual = fromB64url(sig);
    if (actual.length !== expected.length || !(0, crypto_1.timingSafeEqual)(actual, expected)) {
        throw new Error('Invalid tenant token signature');
    }
    let claims;
    try {
        claims = JSON.parse(fromB64url(payload).toString('utf8'));
    }
    catch {
        throw new Error('Malformed tenant token payload');
    }
    const now = Math.floor(Date.now() / 1000);
    if (typeof claims.exp !== 'number' || claims.exp < now)
        throw new Error('Tenant token expired');
    if (!claims.tenantId)
        throw new Error('Tenant token missing tenantId');
    if (opts.expectedAppSlug && claims.appSlug !== opts.expectedAppSlug) {
        throw new Error(`Tenant token issued for app "${claims.appSlug}", not "${opts.expectedAppSlug}"`);
    }
    return claims;
}
/**
 * Express-style middleware factory for extension services: verifies the token
 * and attaches `req.tenantContext`. Skips paths in `publicPaths` (health checks).
 */
function tenantContextMiddleware(options) {
    const publicPaths = new Set(options.publicPaths || []);
    return (req, res, next) => {
        if (publicPaths.has(req.path))
            return next();
        const token = req.headers?.[exports.TENANT_TOKEN_HEADER];
        try {
            req.tenantContext = verifyTenantToken(String(token || ''), options.secret, {
                expectedAppSlug: options.appSlug,
            });
            return next();
        }
        catch (e) {
            const message = e instanceof Error ? e.message : 'Invalid tenant token';
            res.status(401).json({
                statusCode: 401,
                error: 'Unauthorized',
                message,
                app: options.appSlug,
            });
        }
    };
}
// ─── RBAC (#1): pure checks + a Nest-compatible guard factory ───
function hasRole(claims, role) {
    return !!claims && Array.isArray(claims.roles) && claims.roles.includes(role);
}
function hasScope(claims, scope) {
    return !!claims && Array.isArray(claims.scopes) && claims.scopes.includes(scope);
}
/** Error carrying an HTTP status so services can map it to a 403 response. */
class ExtForbiddenError extends Error {
    statusCode = 403;
    constructor(message) {
        super(message);
        this.name = 'ExtForbiddenError';
    }
}
exports.ExtForbiddenError = ExtForbiddenError;
/**
 * Assert the token carries every required scope (or, if `mode: "any"`, at least
 * one). Throws ExtForbiddenError otherwise.
 */
function assertScopes(claims, required, mode = 'all') {
    if (!claims)
        throw new ExtForbiddenError('No tenant context');
    if (required.length === 0)
        return;
    const have = new Set(claims.scopes || []);
    const ok = mode === 'any' ? required.some((s) => have.has(s)) : required.every((s) => have.has(s));
    if (!ok) {
        throw new ExtForbiddenError(`Missing required scope(s): ${required.join(mode === 'any' ? ' | ' : ', ')}`);
    }
}
/**
 * A Nest-compatible guard factory (implemented without importing @nestjs/*).
 * Usage in a service controller:  @UseGuards(RequireScopes('healthcare:write'))
 */
function RequireScopes(...scopes) {
    return class ScopeGuard {
        canActivate(context) {
            const req = context.switchToHttp().getRequest();
            assertScopes(req.tenantContext, scopes, 'all');
            return true;
        }
    };
}
function RequireAnyScope(...scopes) {
    return class AnyScopeGuard {
        canActivate(context) {
            const req = context.switchToHttp().getRequest();
            assertScopes(req.tenantContext, scopes, 'any');
            return true;
        }
    };
}
// ─── Webhooks (#6): sign/verify core→service event deliveries ───
/** Sign a webhook body. Returns the value for WEBHOOK_SIGNATURE_HEADER. */
function signWebhook(rawBody, secret, timestamp) {
    return 'v1=' + hs256(`${timestamp}.${rawBody}`, secret).toString('hex');
}
/**
 * Verify a webhook signature within `toleranceSec` of the timestamp. Throws on
 * mismatch or stale timestamp (replay protection).
 */
function verifyWebhook(rawBody, signatureHeader, timestampHeader, secret, toleranceSec = 300) {
    const ts = Number(timestampHeader);
    if (!ts || Number.isNaN(ts))
        throw new Error('Missing/invalid webhook timestamp');
    if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSec) {
        throw new Error('Webhook timestamp outside tolerance (possible replay)');
    }
    const expected = signWebhook(rawBody, secret, ts);
    if (!signatureHeader || !safeEqualStr(signatureHeader, expected)) {
        throw new Error('Invalid webhook signature');
    }
}
// ─── Versioning (#7): semver compare for minCoreVersion checks ───
function compareSemver(a, b) {
    const pa = a.split('-')[0].split('.').map(Number);
    const pb = b.split('-')[0].split('.').map(Number);
    for (let i = 0; i < 3; i++) {
        const d = (pa[i] || 0) - (pb[i] || 0);
        if (d !== 0)
            return d > 0 ? 1 : -1;
    }
    return 0;
}
/** True when `coreVersion` >= `minCoreVersion`. */
function satisfiesMinCoreVersion(coreVersion, minCoreVersion) {
    if (!minCoreVersion)
        return true;
    return compareSemver(coreVersion, minCoreVersion) >= 0;
}
/**
 * Typed client for the core ext-callback API. Services construct it per request
 * with the raw tenant token they received, and core authorizes by that token
 * (scoped to the app's own schemas).
 */
class CoreClient {
    opts;
    constructor(opts) {
        this.opts = opts;
    }
    base() {
        return `${this.opts.coreApiUrl.replace(/\/+$/, '')}/api/v1/ext-callback`;
    }
    headers() {
        return { 'content-type': 'application/json', [exports.TENANT_TOKEN_HEADER]: this.opts.token };
    }
    /** Read all/filtered records for one provisioned schema slug. */
    async records(schemaSlug, filter) {
        const qs = new URLSearchParams();
        if (filter?.where)
            qs.set('where', JSON.stringify(filter.where));
        if (filter?.limit)
            qs.set('limit', String(filter.limit));
        const q = qs.toString();
        const res = await fetch(`${this.base()}/records/${schemaSlug}${q ? `?${q}` : ''}`, {
            headers: this.headers(),
        });
        if (!res.ok)
            return [];
        const rows = await res.json().catch(() => []);
        return Array.isArray(rows) ? rows : [];
    }
    /** Fetch several schemas at once (one round trip). Returns a slug→rows map. */
    async recordsBatch(schemaSlugs) {
        const res = await fetch(`${this.base()}/records:batch`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify({ slugs: schemaSlugs }),
        });
        if (!res.ok)
            return Object.fromEntries(schemaSlugs.map((s) => [s, []]));
        return (await res.json().catch(() => ({})));
    }
    /** Create a record in a provisioned schema (requires a *:write* scope in the token). */
    async createRecord(schemaSlug, data) {
        const res = await fetch(`${this.base()}/records/${schemaSlug}`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify({ data }),
        });
        if (!res.ok)
            throw new Error(`createRecord ${schemaSlug} failed: ${res.status}`);
        return (await res.json());
    }
}
exports.CoreClient = CoreClient;
