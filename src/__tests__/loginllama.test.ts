jest.mock("./../api", () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => {
      return {
        // @ts-ignore
        post: jest.fn((endpoint: string, data: any) => {
          if (data.identity_key === "validUser") {
            return Promise.resolve({
              status: "success",
              message: "Valid login",
              codes: [LoginCheckStatus.VALID],
              risk_score: 2,
              environment: "staging",
              meta: {},
            });
          } else {
            return Promise.reject({
              status: "error",
              message: "Login check failed",
              risk_score: 9,
              environment: "production",
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
    expect(result.message).toBe("Valid login");
    expect(result.codes).toContain(LoginCheckStatus.VALID);
    expect(result.risk_score).toBe(2);
    expect(result.environment).toBe("staging");
  });

  it("should throw error for invalid login", async () => {
    await expect(
      loginLlama.check("invalidUser", {
        ipAddress: "192.168.1.1",
        userAgent: "Mozilla/5.0",
      })
    ).rejects.toEqual({
      status: "error",
      message: "Login check failed",
      risk_score: 9,
      environment: "production",
    });
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
    expect(result.message).toBe("Valid login");
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
