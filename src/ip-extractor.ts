const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/,
];

/**
 * Extracts IP address from request with multi-source priority fallback
 * and private IP filtering for proxy/CDN scenarios.
 */
export class IPExtractor {
  /**
   * Extract IP address from request with priority fallback
   *
   * Priority order:
   * 1. X-Forwarded-For (first non-private IP)
   * 2. CF-Connecting-IP (Cloudflare)
   * 3. X-Real-IP (nginx)
   * 4. True-Client-IP (Akamai/Cloudflare)
   * 5. Direct connection IP
   *
   * @param request - Express/Next.js request object or similar
   * @returns IP address or undefined
   */
  static extract(request: any): string | undefined {
    if (!request) return undefined;

    // Priority 1: X-Forwarded-For (parse chain, skip private IPs)
    const xForwardedFor = this.getHeader(request, "x-forwarded-for");
    if (xForwardedFor) {
      const ip = this.parseForwardedFor(xForwardedFor);
      if (ip) return ip;
    }

    // Priority 2: CF-Connecting-IP (Cloudflare)
    const cfIP = this.getHeader(request, "cf-connecting-ip");
    if (cfIP && this.isValidPublicIP(cfIP)) return cfIP;

    // Priority 3: X-Real-IP (nginx)
    const realIP = this.getHeader(request, "x-real-ip");
    if (realIP && this.isValidPublicIP(realIP)) return realIP;

    // Priority 4: True-Client-IP (Akamai, Cloudflare)
    const trueClientIP = this.getHeader(request, "true-client-ip");
    if (trueClientIP && this.isValidPublicIP(trueClientIP)) return trueClientIP;

    // Priority 5: Direct connection
    return this.getDirectIP(request);
  }

  /**
   * Parse X-Forwarded-For header and return first public IP
   * Format: "client, proxy1, proxy2"
   */
  private static parseForwardedFor(header: string): string | undefined {
    const ips = header.split(",").map((ip) => ip.trim());
    // Return first public IP in the chain
    return ips.find((ip) => this.isValidPublicIP(ip));
  }

  /**
   * Check if IP is valid and public (not private/local)
   */
  private static isValidPublicIP(ip: string): boolean {
    if (!this.isValidIP(ip)) return false;
    return !PRIVATE_IP_RANGES.some((range) => range.test(ip));
  }

  /**
   * Validate IPv4 or IPv6 address format
   */
  private static isValidIP(ip: string): boolean {
    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const parts = ip.split(".");
      return parts.every((part) => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
      });
    }

    // IPv6 validation (simplified)
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Regex.test(ip);
  }

  /**
   * Get header value from request (handles Express, Next.js, etc.)
   */
  private static getHeader(request: any, name: string): string | undefined {
    // Express: req.headers (object with lowercase keys)
    if (request?.headers) {
      const lowerName = name.toLowerCase();
      const value = request.headers[lowerName] || request.headers[name];
      return typeof value === "string" ? value : value?.[0];
    }

    // Next.js: req.headers.get()
    if (request?.headers?.get) {
      return request.headers.get(name) || undefined;
    }

    return undefined;
  }

  /**
   * Get direct connection IP from request
   */
  private static getDirectIP(request: any): string | undefined {
    // Express: req.ip (trust proxy setting)
    if (request?.ip) return request.ip;

    // Express: req.socket.remoteAddress
    if (request?.socket?.remoteAddress) return request.socket.remoteAddress;

    // Express: req.connection.remoteAddress (deprecated but still used)
    if (request?.connection?.remoteAddress) return request.connection.remoteAddress;

    // Next.js: req.ip
    if (request?.ip) return request.ip;

    return undefined;
  }
}
