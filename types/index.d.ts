/*
 * corscage TypeScript definitions.
 * These definitions are hand-authored to match the runtime API exactly.
 */

export interface CorsCageErrorShape {
  name: 'CorsCageError';
  code: string;
  reason: string;
  input: unknown;
  findings?: readonly LintFinding[];
}

export class CorsCageError extends Error implements CorsCageErrorShape {
  readonly name: 'CorsCageError';
  readonly code: string;
  readonly reason: string;
  readonly input: unknown;
  readonly findings?: readonly LintFinding[];
  toJSON(): CorsCageErrorShape;
}

export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_CORSCAGE_INVALID_INPUT';
  INVALID_OPTIONS: 'ERR_CORSCAGE_INVALID_OPTIONS';
  UNSAFE_CONFIG: 'ERR_CORSCAGE_UNSAFE_CONFIG';
}>;

export const LINT_CODES: Readonly<{
  CONFIG_INVALID: 'CORS_CONFIG_INVALID';
  UNKNOWN_OPTION: 'CORS_UNKNOWN_OPTION';
  WILDCARD_WITH_CREDENTIALS: 'CORS_WILDCARD_WITH_CREDENTIALS';
  NULL_ORIGIN_ALLOWED: 'CORS_NULL_ORIGIN_ALLOWED';
  REFLECT_ALL_ORIGINS: 'CORS_REFLECT_ALL_ORIGINS';
  INSECURE_HTTP_WITH_CREDENTIALS: 'CORS_INSECURE_HTTP_WITH_CREDENTIALS';
  INSECURE_HTTP_ORIGIN: 'CORS_INSECURE_HTTP_ORIGIN';
  OVERBROAD_SUBDOMAIN_WILDCARD: 'CORS_OVERBROAD_SUBDOMAIN_WILDCARD';
  EXCESSIVE_MAX_AGE: 'CORS_EXCESSIVE_MAX_AGE';
  INVALID_MAX_AGE: 'CORS_INVALID_MAX_AGE';
  PRIVATE_NETWORK_WITH_WILDCARD: 'CORS_PRIVATE_NETWORK_WITH_WILDCARD';
  UNSAFE_EXPOSE_HEADER: 'CORS_UNSAFE_EXPOSE_HEADER';
  UNSAFE_ALLOWED_HEADER: 'CORS_UNSAFE_ALLOWED_HEADER';
  INVALID_ORIGIN_ENTRY: 'CORS_INVALID_ORIGIN_ENTRY';
  INVALID_HEADER_ENTRY: 'CORS_INVALID_HEADER_ENTRY';
  INVALID_METHOD_ENTRY: 'CORS_INVALID_METHOD_ENTRY';
  DUPLICATE_ORIGIN: 'CORS_DUPLICATE_ORIGIN';
  NO_ORIGINS_CONFIGURED: 'CORS_NO_ORIGINS_CONFIGURED';
  REDUNDANT_ORIGIN_ENTRY: 'CORS_REDUNDANT_ORIGIN_ENTRY';
}>;

export type OriginHostType = 'domain' | 'ipv4' | 'ipv6' | null;

export interface ParsedOrigin {
  readonly valid: boolean;
  readonly isNull: boolean;
  readonly normalized: string | null;
  readonly scheme: 'http' | 'https' | null;
  readonly host: string | null;
  readonly port: number | null;
  readonly explicitPort: number | null;
  readonly isDefaultPort: boolean;
  readonly hostType: OriginHostType;
  readonly isLocalhost: boolean;
  readonly code: string;
  readonly reason: string;
}

export interface MatchOriginOptions {
  readonly multiLevelSubdomain?: boolean;
}

export interface OriginPredicateContext {
  readonly origin: string;
  readonly scheme: 'http' | 'https';
  readonly host: string;
  readonly port: number;
  readonly hostType: 'domain' | 'ipv4' | 'ipv6';
  readonly isLocalhost: boolean;
}

export interface CorsPolicyOptions {
  readonly allowedOrigins?: string | readonly string[];
  readonly credentials?: boolean;
  readonly methods?: string | readonly string[];
  readonly allowedHeaders?: string | readonly string[];
  readonly exposeHeaders?: string | readonly string[];
  readonly maxAge?: number;
  readonly allowNullOrigin?: boolean;
  readonly allowHttpLocalhost?: boolean;
  readonly multiLevelSubdomain?: boolean;
  readonly allowPrivateNetwork?: boolean;
  readonly rejectDisallowedPreflight?: boolean;
  readonly originPredicate?: (origin: OriginPredicateContext) => boolean;
  readonly maxRequestHeaders?: number;
  readonly maxRequestHeadersBytes?: number;
  readonly allowForbiddenHeaders?: boolean;
}

export interface PublicCorsPolicyConfig {
  readonly allowedOrigins: readonly string[];
  readonly credentials: boolean;
  readonly methods: readonly string[];
  readonly allowedHeaders: readonly string[];
  readonly exposeHeaders: readonly string[];
  readonly maxAge: number;
  readonly allowNullOrigin: boolean;
  readonly allowHttpLocalhost: boolean;
  readonly multiLevelSubdomain: boolean;
  readonly allowPrivateNetwork: boolean;
  readonly rejectDisallowedPreflight: boolean;
  readonly maxRequestHeaders: number;
  readonly maxRequestHeadersBytes: number;
  readonly allowForbiddenHeaders: boolean;
  readonly hasOriginPredicate: boolean;
}

export type HeaderMap = Readonly<Record<string, string>>;

export interface CorsEvaluation {
  readonly allowed: boolean;
  readonly isPreflight: boolean;
  readonly statusCode: 204 | 403 | null;
  readonly headers: HeaderMap;
  readonly vary: readonly string[];
  readonly reason: string;
  readonly code: string;
  readonly origin: string | null;
  readonly removeHeaders: readonly string[];
}

export interface CorsPolicy {
  readonly config: PublicCorsPolicyConfig;
  evaluate(requestLike: unknown): CorsEvaluation;
  isOriginAllowed(origin: unknown): boolean;
  match(origin: unknown): boolean;
}

export interface NodeRequestLike {
  readonly method?: string;
  readonly headers?: Record<string, string | string[] | undefined>;
}

export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | number | readonly string[]): void;
  getHeader?(name: string): unknown;
  removeHeader?(name: string): void;
  end?(chunk?: unknown): void;
  readonly headers?: Record<string, unknown>;
}

export type NodeNextFunction = (error?: unknown) => void;
export type NodeCorsMiddleware = {
  (req: NodeRequestLike, res: NodeResponseLike, next?: NodeNextFunction): void;
};

export type FetchHandler<Args extends unknown[] = unknown[]> = (
  request: Request,
  ...args: Args
) => Response | Promise<Response>;

export type WrappedFetchHandler<Args extends unknown[] = unknown[]> = (
  request: Request,
  ...args: Args
) => Promise<Response>;

export type LintSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface LintFinding {
  readonly code: string;
  readonly severity: LintSeverity;
  readonly message: string;
  readonly remediation: string;
  readonly path: string | null;
}

export function parseOrigin(input: unknown): ParsedOrigin;
export function normalizeOrigin(input: unknown): string | null;
export function matchOrigin(candidate: unknown, pattern: unknown, options?: MatchOriginOptions): boolean;
export function mergeVary(existing: unknown, tokens: unknown): string;
export function createCorsPolicy(options?: CorsPolicyOptions): CorsPolicy;
export function createNodeCorsMiddleware(options?: CorsPolicyOptions): NodeCorsMiddleware;
export function createFetchCorsHandler(options?: CorsPolicyOptions): <Args extends unknown[]>(handler: FetchHandler<Args>) => WrappedFetchHandler<Args>;
export function createFetchCorsHandler<Args extends unknown[]>(options: CorsPolicyOptions, handler: FetchHandler<Args>): WrappedFetchHandler<Args>;
export function lintCorsPolicy(options: unknown): readonly LintFinding[];
export function assertSafeCorsConfig(options: unknown): true;

declare const corscage: {
  readonly CODE: typeof CODE;
  readonly LINT_CODES: typeof LINT_CODES;
  readonly CorsCageError: typeof CorsCageError;
  readonly parseOrigin: typeof parseOrigin;
  readonly normalizeOrigin: typeof normalizeOrigin;
  readonly matchOrigin: typeof matchOrigin;
  readonly mergeVary: typeof mergeVary;
  readonly createCorsPolicy: typeof createCorsPolicy;
  readonly createNodeCorsMiddleware: typeof createNodeCorsMiddleware;
  readonly createFetchCorsHandler: typeof createFetchCorsHandler;
  readonly lintCorsPolicy: typeof lintCorsPolicy;
  readonly assertSafeCorsConfig: typeof assertSafeCorsConfig;
};

export default corscage;
