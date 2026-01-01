import { AsyncLocalStorage } from "async_hooks";
import { IPExtractor } from "./ip-extractor";

// Global storage for request context
const requestContext = new AsyncLocalStorage<RequestContext>();

export interface RequestContext {
  ipAddress?: string;
  userAgent?: string;
  framework?: "express" | "nextjs" | "unknown";
  rawRequest?: unknown;
}

/**
 * Context detector for automatically capturing request information
 * using AsyncLocalStorage for async-safe context propagation.
 */
export class ContextDetector {
  /**
   * Store request context for this async scope
   * @param request - Express/Next.js request object
   */
  static setContext(request: any): void {
    const context: RequestContext = {
      ipAddress: IPExtractor.extract(request),
      userAgent: this.extractUserAgent(request),
      framework: this.detectFramework(request),
      rawRequest: request,
    };
    requestContext.enterWith(context);
  }

  /**
   * Retrieve current request context from async storage
   * @returns Request context or undefined if not set
   */
  static getContext(): RequestContext | undefined {
    return requestContext.getStore();
  }

  /**
   * Clear context (usually not needed as it's scoped to async context)
   */
  static clearContext(): void {
    // Context is automatically cleared when async scope exits
    // This method exists for manual cleanup if needed
  }

  /**
   * Detect which framework the request is from
   */
  private static detectFramework(
    request: any
  ): RequestContext["framework"] {
    if (!request) return "unknown";

    // Express: has app._router
    if (request?.app?._router) return "express";

    // Next.js: has nextUrl property
    if (request?.nextUrl) return "nextjs";

    return "unknown";
  }

  /**
   * Extract User-Agent from request headers
   */
  private static extractUserAgent(request: any): string | undefined {
    if (!request) return undefined;

    // Express: req.headers (object with lowercase keys)
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
