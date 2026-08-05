/** Current contract version exposed by core and extension services. */
export declare const EXT_API_VERSION = 1;
/** Oldest extension contract still accepted by this core release. */
export declare const MIN_SUPPORTED_EXT_API_VERSION = 1;
/** True when an extension's declared contract is within the supported range. */
export declare function isSupportedExtApiVersion(version: number): boolean;
/** Header carrying the signed tenant-context token on proxied requests. */
export declare const TENANT_TOKEN_HEADER = "x-unierp-tenant-token";
/** Correlation id propagated from the gateway. */
export declare const REQUEST_ID_HEADER = "x-request-id";
/** Signature + timestamp headers on core→service event webhooks. */
export declare const WEBHOOK_SIGNATURE_HEADER = "x-unierp-signature";
export declare const WEBHOOK_TIMESTAMP_HEADER = "x-unierp-timestamp";
/** Default TTL for tenant-context tokens (seconds). */
export declare const TENANT_TOKEN_TTL_SECONDS = 60;
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
export declare function buildHealthResponse(app: string, version?: string): ExtHealthResponse;
/** Sign a tenant-context token (HS256). Used by core's gateway. */
export declare function signTenantToken(claims: Omit<TenantContextClaims, 'iat' | 'exp'>, secret: string, ttlSeconds?: number): string;
/**
 * Decode a token's claims WITHOUT verifying the signature. Only for selecting
 * which per-app secret to verify with — never trust the result before calling
 * verifyTenantToken.
 */
export declare function decodeTokenUnverified(token: string): Partial<TenantContextClaims> | null;
/**
 * Verify a tenant-context token. Throws on any problem (bad signature, expired,
 * wrong app). Returns the claims on success.
 */
export declare function verifyTenantToken(token: string, secret: string, opts?: {
    expectedAppSlug?: string;
}): TenantContextClaims;
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
export declare function tenantContextMiddleware(options: {
    secret: string;
    appSlug: string;
    publicPaths?: string[];
}): (req: MinimalRequest, res: MinimalResponse, next: NextFn) => void;
export declare function hasRole(claims: TenantContextClaims | undefined, role: string): boolean;
export declare function hasScope(claims: TenantContextClaims | undefined, scope: string): boolean;
/** Error carrying an HTTP status so services can map it to a 403 response. */
export declare class ExtForbiddenError extends Error {
    statusCode: number;
    constructor(message: string);
}
/**
 * Assert the token carries every required scope (or, if `mode: "any"`, at least
 * one). Throws ExtForbiddenError otherwise.
 */
export declare function assertScopes(claims: TenantContextClaims | undefined, required: string[], mode?: 'all' | 'any'): void;
/**
 * Structural stand-in for Nest's ExecutionContext — service-kit has no
 * @nestjs/* dependency, but this shape matches it closely enough that a real
 * ExecutionContext satisfies it at the call site.
 */
export interface MinimalExecutionContext {
    switchToHttp(): {
        getRequest(): MinimalRequest;
    };
}
/**
 * A Nest-compatible guard factory (implemented without importing @nestjs/*).
 * Usage in a service controller:  @UseGuards(RequireScopes('healthcare:write'))
 */
export declare function RequireScopes(...scopes: string[]): {
    new (): {
        canActivate(context: MinimalExecutionContext): boolean;
    };
};
export declare function RequireAnyScope(...scopes: string[]): {
    new (): {
        canActivate(context: MinimalExecutionContext): boolean;
    };
};
/** Sign a webhook body. Returns the value for WEBHOOK_SIGNATURE_HEADER. */
export declare function signWebhook(rawBody: string, secret: string, timestamp: number): string;
/**
 * Verify a webhook signature within `toleranceSec` of the timestamp. Throws on
 * mismatch or stale timestamp (replay protection).
 */
export declare function verifyWebhook(rawBody: string, signatureHeader: string, timestampHeader: string | number, secret: string, toleranceSec?: number): void;
export declare function compareSemver(a: string, b: string): number;
/** True when `coreVersion` >= `minCoreVersion`. */
export declare function satisfiesMinCoreVersion(coreVersion: string, minCoreVersion?: string): boolean;
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
export declare class CoreClient {
    private readonly opts;
    constructor(opts: {
        coreApiUrl: string;
        token: string;
    });
    private base;
    private headers;
    /** Read all/filtered records for one provisioned schema slug. */
    records(schemaSlug: string, filter?: CoreRecordFilter): Promise<Record<string, unknown>[]>;
    /** Fetch several schemas at once (one round trip). Returns a slug→rows map. */
    recordsBatch(schemaSlugs: string[]): Promise<Record<string, Record<string, unknown>[]>>;
    /** Create a record in a provisioned schema (requires a *:write* scope in the token). */
    createRecord(schemaSlug: string, data: Record<string, unknown>): Promise<Record<string, unknown>>;
}
