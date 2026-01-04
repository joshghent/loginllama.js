import Api from "./api";
import crypto from "crypto";
import { ContextDetector } from "./context-detector";
import { IPExtractor } from "./ip-extractor";
import {
  AuthenticationOutcome,
  CheckOptions,
  LoginCheckResponse,
  LoginCheckStatus,
} from "./types";

const API_ENDPOINT =
  process.env["LOGINLLAMA_API_BASE_URL"] || "https://loginllama.app/api/v1";

// Re-export types for convenience
export {
  AuthenticationOutcome,
  CheckOptions,
  LoginCheckResponse,
  LoginCheckStatus,
};

/**
 * Verify webhook signature using HMAC-SHA256
 *
 * @param payload - Webhook payload (string or Buffer)
 * @param signature - X-LoginLlama-Signature header value
 * @param secret - Webhook secret from LoginLlama dashboard
 * @returns true if signature is valid
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string | undefined,
  secret: string
): boolean {
  if (!signature || !secret) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  // Use constant-time comparison to avoid timing attacks
  const safeSignature = Buffer.from(signature, "hex");
  const safeExpected = Buffer.from(expectedSignature, "hex");

  if (safeSignature.length !== safeExpected.length) {
    return false;
  }

  return crypto.timingSafeEqual(safeSignature, safeExpected);
}

/**
 * LoginLlama client for detecting suspicious login attempts
 */
export class LoginLlama {
  private api: Api;
  private token: string;

  /**
   * Create a new LoginLlama client
   *
   * @param apiKey - API key (defaults to LOGINLLAMA_API_KEY env var)
   * @param baseUrl - Base URL for API (defaults to https://loginllama.app/api/v1)
   */
  constructor({
    apiKey,
    baseUrl,
  }: {
    apiKey?: string;
    baseUrl?: string;
  } = {}) {
    this.token = apiKey || String(process.env["LOGINLLAMA_API_KEY"] || "");
    this.api = new Api(
      {
        "X-API-KEY": this.token,
      },
      baseUrl || API_ENDPOINT
    );
  }

  /**
   * Check a login attempt for suspicious activity
   *
   * IP address and User-Agent are automatically detected from:
   * 1. Explicit overrides in options
   * 2. Explicit request object in options
   * 3. Async context (if middleware is used)
   *
   * @param identityKey - User identifier (email, username, user ID, etc.)
   * @param options - Optional overrides and additional context
   * @returns Promise resolving to login check result
   *
   * @example
   * // Auto-detect from middleware context
   * app.use(loginllama.middleware());
   * app.post('/login', async (req, res) => {
   *   const result = await loginllama.check('user@example.com');
   *   if (result.risk_score > 5) {
   *     return res.status(403).json({ error: 'Suspicious login' });
   *   }
   * });
   *
   * @example
   * // Explicit request passing
   * app.post('/login', async (req, res) => {
   *   const result = await loginllama.check('user@example.com', { request: req });
   * });
   *
   * @example
   * // Manual override
   * const result = await loginllama.check('user@example.com', {
   *   ipAddress: '1.2.3.4',
   *   userAgent: 'Custom/1.0',
   *   emailAddress: 'user@example.com'
   * });
   */
  public async check(
    identityKey: string,
    options: CheckOptions = {}
  ): Promise<LoginCheckResponse> {
    if (!identityKey) {
      throw new Error("identityKey is required");
    }

    // Extract IP and User-Agent with priority fallback
    let ipAddress: string | undefined;
    let userAgent: string | undefined;

    // Priority 1: Explicit overrides
    if (options.ipAddress) {
      ipAddress = options.ipAddress;
    }
    if (options.userAgent) {
      userAgent = options.userAgent;
    }

    // Priority 2: Extract from explicit request
    if (options.request && (!ipAddress || !userAgent)) {
      if (!ipAddress) {
        ipAddress = IPExtractor.extract(options.request);
      }
      if (!userAgent) {
        userAgent = this.extractUserAgent(options.request);
      }
    }

    // Priority 3: Check async context (from middleware)
    if (!ipAddress || !userAgent) {
      const context = ContextDetector.getContext();
      if (context) {
        if (!ipAddress) ipAddress = context.ipAddress;
        if (!userAgent) userAgent = context.userAgent;
      }
    }

    // Validation
    if (!ipAddress) {
      throw new Error(
        "IP address could not be detected. Pass { ipAddress } or { request } explicitly, or use the middleware() function."
      );
    }
    if (!userAgent) {
      throw new Error(
        "User-Agent could not be detected. Pass { userAgent } or { request } explicitly, or use the middleware() function."
      );
    }

    // Make API call
    return this.api.post("/login/check", {
      ip_address: ipAddress,
      user_agent: userAgent,
      identity_key: identityKey,
      email_address: options.emailAddress,
      geo_country: options.geoCountry,
      geo_city: options.geoCity,
      user_time_of_day: options.userTimeOfDay,
      authentication_outcome: options.authenticationOutcome,
    });
  }

  /**
   * Report a successful authentication
   *
   * Use this after the user has successfully authenticated with your system.
   * This is a convenience method equivalent to:
   * `check(identityKey, { ...options, authenticationOutcome: 'success' })`
   *
   * @param identityKey - User identifier (email, username, user ID, etc.)
   * @param options - Optional overrides and additional context
   * @returns Promise resolving to login check result
   *
   * @example
   * // After successful login
   * const authResult = await authenticate(email, password);
   * if (authResult.success) {
   *   await loginllama.reportSuccess(user.id, { request: req });
   * }
   */
  public async reportSuccess(
    identityKey: string,
    options: Omit<CheckOptions, "authenticationOutcome"> = {}
  ): Promise<LoginCheckResponse> {
    return this.check(identityKey, {
      ...options,
      authenticationOutcome: "success",
    });
  }

  /**
   * Report a failed authentication attempt
   *
   * Use this when the user's credentials are invalid (wrong password, MFA failed, etc.).
   * This helps LoginLlama detect brute force and credential stuffing attacks.
   *
   * @param identityKey - User identifier (email, username, user ID, etc.)
   * @param options - Optional overrides and additional context
   * @returns Promise resolving to login check result
   *
   * @example
   * // After failed login
   * const authResult = await authenticate(email, password);
   * if (!authResult.success) {
   *   await loginllama.reportFailure(email, { request: req });
   * }
   */
  public async reportFailure(
    identityKey: string,
    options: Omit<CheckOptions, "authenticationOutcome"> = {}
  ): Promise<LoginCheckResponse> {
    return this.check(identityKey, {
      ...options,
      authenticationOutcome: "failed",
    });
  }

  /**
   * Create middleware for Express/Next.js to auto-capture request context
   *
   * This middleware stores request information in AsyncLocalStorage,
   * allowing check() to automatically access IP and User-Agent.
   *
   * @returns Middleware function
   *
   * @example
   * // Express
   * const loginllama = new LoginLlama();
   * app.use(loginllama.middleware());
   *
   * app.post('/login', async (req, res) => {
   *   const result = await loginllama.check(req.body.email);
   *   // IP and User-Agent automatically detected
   * });
   *
   * @example
   * // Next.js App Router (middleware.ts)
   * import { LoginLlama } from 'loginllama';
   * import { NextResponse } from 'next/server';
   *
   * const loginllama = new LoginLlama();
   *
   * export function middleware(request: NextRequest) {
   *   loginllama.middleware()(request, null, () => {});
   *   return NextResponse.next();
   * }
   */
  public middleware() {
    return (req: any, _res: any, next: any) => {
      ContextDetector.setContext(req);
      if (next) next();
    };
  }

  /**
   * Extract User-Agent from request
   * @private
   */
  private extractUserAgent(request: any): string | undefined {
    if (!request) return undefined;

    // Express: req.headers
    if (request?.headers) {
      const value =
        request.headers["user-agent"] || request.headers["User-Agent"];
      return typeof value === "string" ? value : value?.[0];
    }

    // Next.js: req.headers.get()
    if (request?.headers?.get) {
      return request.headers.get("user-agent") || undefined;
    }

    return undefined;
  }
}
