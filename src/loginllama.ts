import Api from "./api";
import { Request } from "express";
import crypto from "crypto";

const API_ENDPOINT =
  process.env["LOGINLLAMA_API_BASE_URL"] || "https://loginllama.app/api/v1";

export enum LoginCheckStatus {
  VALID = "login_valid",
  IP_ADDRESS_SUSPICIOUS = "ip_address_suspicious",
  DEVICE_FINGERPRINT_SUSPICIOUS = "device_fingerprint_suspicious",
  LOCATION_FINGERPRINT_SUSPICIOUS = "location_fingerprint_suspicious",
  BEHAVIORAL_FINGERPRINT_SUSPICIOUS = "behavioral_fingerprint_suspicious",
  KNOWN_TOR_EXIT_NODE = "known_tor_exit_node",
  KNOWN_PROXY = "known_proxy",
  KNOWN_VPN = "known_vpn",
  KNOWN_BOTNET = "known_botnet",
  KNOWN_BOT = "known_bot",
  IP_ADDRESS_NOT_USED_BEFORE = "ip_address_not_used_before",
  DEVICE_FINGERPRINT_NOT_USED_BEFORE = "device_fingerprint_not_used_before",
  AI_DETECTED_SUSPICIOUS = "ai_detected_suspicious",
}

export interface LoginCheckResponse {
  status: "success" | "error";
  message: string;
  codes: LoginCheckStatus[];
  risk_score: number;
  environment: "production" | "staging" | string;
  meta?: Record<string, unknown>;
  error?: string;
}

type LoginCheckRequest = {
  request?: Request;
  ipAddress?: string;
  userAgent?: string;
  identityKey?: string;
  emailAddress?: string;
  geoCountry?: string;
  geoCity?: string;
  userTimeOfDay?: string;
  // Backwards compatible snake_case inputs
  ip_address?: string;
  user_agent?: string;
  identity_key?: string;
  email_address?: string;
  geo_country?: string;
  geo_city?: string;
  user_time_of_day?: string;
};

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

export class LoginLlama {
  private api;
  private token: string;

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
   * Checks the login status of a user.
   *
   * @param {Object} params - The parameters for the login check.
   * @param {Request} [params.request] - An Express request object. Optional.
   * @param {string} [params.ip_address] - The IP address of the user. If not provided, it will be extracted from the request object. Optional.
   * @param {string} [params.user_agent] - The user agent string of the user. If not provided, it will be extracted from the request object. Optional.
   * @param {string} params.identity_key - The unique identity key for the user.
   *
   * @returns {Promise<LoginCheck>} - A promise that resolves to a `LoginCheck` object containing the result of the login check.
   *
   * @example
   * const loginCheckResult = await check_login({
   *   ip_address: "192.168.1.1",
   *   user_agent: "Mozilla/5.0",
   *   identity_key: "user123"
   * });
   *
   * @example
   * const loginCheckResult = await check_login({
   *  request: req,
   *  identity_key: "user123"
   * });
   */
  public async checkLogin(requestParams: LoginCheckRequest): Promise<LoginCheckResponse> {
    const {
      request,
      ipAddress,
      userAgent,
      identityKey,
      emailAddress,
      geoCountry,
      geoCity,
      userTimeOfDay,
      ip_address,
      user_agent,
      identity_key,
      email_address,
      geo_country,
      geo_city,
      user_time_of_day,
    } = requestParams;

    let finalIp = ipAddress || ip_address;
    let finalUserAgent = userAgent || user_agent;
    const finalIdentityKey = identityKey || identity_key;

    if (request) {
      finalIp =
        request.ip ||
        request.ips?.[0] ||
        (request.headers["x-forwarded-for"] as string) ||
        request.socket.remoteAddress ||
        "Unavailable";
      finalUserAgent = (request.headers["user-agent"] as string) || finalUserAgent;
    }

    if (!finalIp) {
      throw new Error("ip_address is required");
    }
    if (!finalUserAgent) {
      throw new Error("user_agent is required");
    }
    if (!finalIdentityKey) {
      throw new Error("identity_key is required");
    }

    return this.api.post("/login/check", {
      ip_address: finalIp,
      user_agent: finalUserAgent,
      identity_key: finalIdentityKey,
      email_address: emailAddress || email_address,
      geo_country: geoCountry || geo_country,
      geo_city: geoCity || geo_city,
      user_time_of_day: userTimeOfDay || user_time_of_day,
    }) as Promise<LoginCheckResponse>;
  }

  // Backwards compatibility
  public async check_login(params: LoginCheckRequest): Promise<LoginCheckResponse> {
    return this.checkLogin(params);
  }
}
