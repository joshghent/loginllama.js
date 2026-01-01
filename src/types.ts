/**
 * Status codes returned by the LoginLlama API
 */
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

/**
 * Response from the LoginLlama API
 */
export interface LoginCheckResponse {
  status: "success" | "error";
  message: string;
  codes: LoginCheckStatus[];
  risk_score: number;
  environment: "production" | "staging" | string;
  meta?: Record<string, unknown>;
  error?: string;
}

/**
 * Options for the check() method
 */
export interface CheckOptions {
  // Override auto-detected values
  ipAddress?: string;
  userAgent?: string;

  // Additional context
  emailAddress?: string;
  geoCountry?: string;
  geoCity?: string;
  userTimeOfDay?: string;

  // For explicit request passing
  request?: any;
}
