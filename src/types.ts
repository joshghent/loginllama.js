/**
 * Status codes returned by the LoginLlama API
 */
export enum LoginCheckStatus {
  VALID = "login_valid",
  INVALID = "login_invalid",
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
  GEO_IMPOSSIBLE_TRAVEL = "geo_impossible_travel",
  GEO_COUNTRY_MISMATCH = "geo_country_mismatch",
  USER_AGENT_SUSPICIOUS = "user_agent_suspicious",
}

/**
 * Internal JSON:API response format from the API
 * @internal
 */
/**
 * Authentication outcome values for tracking login results
 */
export type AuthenticationOutcome = "success" | "failed" | "pending";

export interface JsonApiResponse {
  data?: {
    type: "login_check";
    attributes: {
      status: "pass" | "fail";
      risk_score: number;
      risk_codes: string[];
      unrecognized_device: boolean;
      authentication_outcome: AuthenticationOutcome;
      message: string;
    };
  };
  meta?: {
    environment: string;
    email_sent: boolean;
  };
  errors?: Array<{
    status: string;
    code: string;
    title: string;
    detail: string;
    source?: { pointer: string };
  }>;
}

/**
 * Public response from the LoginLlama API
 * This is the user-facing format documented in the README
 */
export interface LoginCheckResponse {
  /** 'success' if the check completed, 'error' if something went wrong */
  status: "success" | "error";
  /** Human-readable message about the result */
  message: string;
  /** Array of detected risk codes */
  codes: LoginCheckStatus[];
  /** Risk score from 0-10. Scores above 5 typically indicate suspicious activity */
  risk_score: number;
  /** API environment (production or staging) */
  environment: "production" | "staging" | string;
  /** Whether an unrecognized device was detected */
  unrecognized_device?: boolean;
  /** Customer's authentication outcome: 'success', 'failed', or 'pending' */
  authentication_outcome?: AuthenticationOutcome;
  /** Whether an email notification was sent to the user */
  email_sent?: boolean;
  /** Additional metadata */
  meta?: Record<string, unknown>;
  /** Error message if status is 'error' */
  error?: string;
}

/**
 * Options for the check() method
 */
export interface CheckOptions {
  /** Override auto-detected IP address */
  ipAddress?: string;
  /** Override auto-detected User-Agent */
  userAgent?: string;

  /** User's email address for additional verification */
  emailAddress?: string;
  /** ISO country code (e.g., 'US', 'GB') */
  geoCountry?: string;
  /** City name for additional context */
  geoCity?: string;
  /** Time of login attempt */
  userTimeOfDay?: string;

  /**
   * Customer's authentication outcome
   * - 'success': User's credentials were valid (default)
   * - 'failed': User's credentials were invalid (wrong password, MFA failed, etc.)
   * - 'pending': Pre-auth check, outcome not yet known
   */
  authenticationOutcome?: AuthenticationOutcome;

  /** Express/Next.js request object for automatic extraction */
  request?: unknown;
}

/**
 * Transform JSON:API response to the public flat format
 * @internal
 */
export function transformApiResponse(
  jsonApi: JsonApiResponse
): LoginCheckResponse {
  // Handle error responses
  if (jsonApi.errors && jsonApi.errors.length > 0) {
    const firstError = jsonApi.errors[0];
    return {
      status: "error",
      message: firstError.detail || firstError.title || "Unknown error",
      codes: [],
      risk_score: 0,
      environment: jsonApi.meta?.environment || "unknown",
      error: firstError.code,
    };
  }

  // Handle success responses
  if (jsonApi.data?.attributes) {
    const attrs = jsonApi.data.attributes;
    return {
      status: attrs.status === "pass" ? "success" : "error",
      message: attrs.message,
      codes: attrs.risk_codes.map((code) => code as LoginCheckStatus),
      risk_score: attrs.risk_score,
      environment: jsonApi.meta?.environment || "production",
      unrecognized_device: attrs.unrecognized_device,
      authentication_outcome: attrs.authentication_outcome,
      email_sent: jsonApi.meta?.email_sent,
    };
  }

  // Fallback for unexpected response format
  return {
    status: "error",
    message: "Unexpected API response format",
    codes: [],
    risk_score: 0,
    environment: "unknown",
    error: "invalid_response",
  };
}
