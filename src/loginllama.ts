import Api from "./api";
import { Request } from "express";

const API_ENDPOINT = "https://loginllama.app/api/v1";

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

export interface LoginCheck {
  status: string;
  message: string;
  codes: LoginCheckStatus[];
}

export class LoginLlama {
  private api;
  private token: string;

  constructor(apiToken?: any) {
    this.token = apiToken || String(process.env["LOGINLLAMA_API_KEY"]);
    this.api = new Api(
      new Headers({
        "X-API-KEY": this.token,
      }),
      API_ENDPOINT
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
  public async check_login({
    request,
    ip_address,
    user_agent,
    identity_key,
  }: {
    request?: Request;
    ip_address?: string;
    user_agent?: string;
    identity_key: string;
  }): Promise<LoginCheck> {
    if (request) {
      ip_address = request.ip || request.ips[0];
      user_agent = request.headers["user-agent"];
    }

    if (!ip_address) {
      throw new Error("ip_address is required");
    }
    if (!user_agent) {
      throw new Error("user_agent is required");
    }
    if (!identity_key) {
      throw new Error("identity_key is required");
    }

    return this.api.post("/check/login", {
      ip_address,
      user_agent,
      identity_key,
    }) as Promise<LoginCheck>;
  }
}
