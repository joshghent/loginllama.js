jest.mock("./../api", () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => {
      return {
        // Mock the post method to return already-transformed responses
        // (since the real API class transforms JSON:API internally)
        post: jest.fn((_endpoint: string, data: any) => {
          if (data.identity_key === "validUser") {
            return Promise.resolve({
              status: "success",
              message: "Login check passed",
              codes: [LoginCheckStatus.VALID],
              risk_score: 2,
              environment: "staging",
              unrecognized_device: false,
              email_sent: false,
            });
          } else {
            return Promise.resolve({
              status: "error",
              message: "Login check failed",
              codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
              risk_score: 9,
              environment: "production",
              unrecognized_device: true,
              email_sent: true,
            });
          }
        }),
      };
    }),
  };
});

import {
  LoginLlama,
  LoginCheckStatus,
  verifyWebhookSignature,
} from "../loginllama";
import { Request } from "express";
import crypto from "crypto";

const mockRequest = (ip: string, userAgent: string): Partial<Request> => {
  return {
    ip: ip,
    ips: [ip],
    headers: {
      "user-agent": userAgent,
    },
  };
};

describe("LoginLlama", () => {
  let loginLlama: LoginLlama;

  beforeEach(() => {
    loginLlama = new LoginLlama({ apiKey: "mockToken" });
  });

  it("should check valid login with explicit parameters", async () => {
    const result = await loginLlama.check("validUser", {
      ipAddress: "192.168.1.1",
      userAgent: "Mozilla/5.0",
    });

    expect(result.status).toBe("success");
    expect(result.message).toBe("Login check passed");
    expect(result.codes).toContain(LoginCheckStatus.VALID);
    expect(result.risk_score).toBe(2);
    expect(result.environment).toBe("staging");
    expect(result.unrecognized_device).toBe(false);
  });

  it("should return error status for suspicious login", async () => {
    const result = await loginLlama.check("invalidUser", {
      ipAddress: "192.168.1.1",
      userAgent: "Mozilla/5.0",
    });

    expect(result.status).toBe("error");
    expect(result.message).toBe("Login check failed");
    expect(result.risk_score).toBe(9);
    expect(result.environment).toBe("production");
    expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
    expect(result.unrecognized_device).toBe(true);
  });

  it("should throw error if IP address cannot be detected", async () => {
    await expect(
      loginLlama.check("validUser", {
        userAgent: "Mozilla/5.0",
      })
    ).rejects.toThrow("IP address could not be detected");
  });

  it("should throw error if User-Agent cannot be detected", async () => {
    await expect(
      loginLlama.check("validUser", {
        ipAddress: "192.168.1.1",
      })
    ).rejects.toThrow("User-Agent could not be detected");
  });

  it("should throw error if identity_key is missing", async () => {
    await expect(
      loginLlama.check("", {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
      })
    ).rejects.toThrow("identityKey is required");
  });

  it("should extract ip_address and user_agent from request object", async () => {
    const req = mockRequest("192.168.1.1", "Mozilla/5.0");

    const result = await loginLlama.check("validUser", {
      request: req as Request,
    });

    expect(result.status).toBe("success");
    expect(result.message).toBe("Login check passed");
    expect(result.codes).toContain(LoginCheckStatus.VALID);
  });

  it("verifies webhook signatures using constant time comparison", () => {
    const payload = JSON.stringify({ event: "login.checked" });
    const secret = "super-secret";
    const signature = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("hex");

    expect(verifyWebhookSignature(payload, signature, secret)).toBe(true);
    expect(verifyWebhookSignature(payload, "deadbeef", secret)).toBe(false);
    expect(verifyWebhookSignature(payload, signature, "wrong-secret")).toBe(false);
  });
});

describe("transformApiResponse", () => {
  const { transformApiResponse } = require("../types");

  it("transforms JSON:API success response to flat format", () => {
    const jsonApi = {
      data: {
        type: "login_check",
        attributes: {
          status: "pass",
          risk_score: 2,
          risk_codes: ["login_valid"],
          unrecognized_device: false,
          message: "Login check passed",
        },
      },
      meta: {
        environment: "production",
        email_sent: false,
      },
    };

    const result = transformApiResponse(jsonApi);

    expect(result.status).toBe("success");
    expect(result.message).toBe("Login check passed");
    expect(result.risk_score).toBe(2);
    expect(result.codes).toEqual(["login_valid"]);
    expect(result.environment).toBe("production");
    expect(result.unrecognized_device).toBe(false);
    expect(result.email_sent).toBe(false);
  });

  it("transforms JSON:API fail response to error status", () => {
    const jsonApi = {
      data: {
        type: "login_check",
        attributes: {
          status: "fail",
          risk_score: 8,
          risk_codes: ["ip_address_suspicious", "known_tor_exit_node"],
          unrecognized_device: true,
          message: "Login check failed",
        },
      },
      meta: {
        environment: "staging",
        email_sent: true,
      },
    };

    const result = transformApiResponse(jsonApi);

    expect(result.status).toBe("error");
    expect(result.message).toBe("Login check failed");
    expect(result.risk_score).toBe(8);
    expect(result.codes).toEqual(["ip_address_suspicious", "known_tor_exit_node"]);
    expect(result.unrecognized_device).toBe(true);
    expect(result.email_sent).toBe(true);
  });

  it("transforms JSON:API error response correctly", () => {
    const jsonApi = {
      errors: [
        {
          status: "401",
          code: "invalid_api_key",
          title: "Invalid API key",
          detail: "The provided API key is not valid",
        },
      ],
    };

    const result = transformApiResponse(jsonApi);

    expect(result.status).toBe("error");
    expect(result.message).toBe("The provided API key is not valid");
    expect(result.error).toBe("invalid_api_key");
    expect(result.codes).toEqual([]);
    expect(result.risk_score).toBe(0);
  });

  it("handles unexpected response format", () => {
    const jsonApi = {};

    const result = transformApiResponse(jsonApi);

    expect(result.status).toBe("error");
    expect(result.message).toBe("Unexpected API response format");
    expect(result.error).toBe("invalid_response");
  });
});
