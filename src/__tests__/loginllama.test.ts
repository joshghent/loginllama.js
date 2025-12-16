jest.mock("./../api", () => {
  return {
    __esModule: true, // this property makes it work as a default export
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

  it("should check valid login", async () => {
    const result = await loginLlama.checkLogin({
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0",
      identity_key: "validUser",
    });

    expect(result.status).toBe("success");
    expect(result.message).toBe("Valid login");
    expect(result.codes).toContain(LoginCheckStatus.VALID);
    expect(result.risk_score).toBe(2);
    expect(result.environment).toBe("staging");
  });

  it("should throw error for invalid login", async () => {
    await expect(
      loginLlama.checkLogin({
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
        identity_key: "invalidUser",
      })
    ).rejects.toEqual({
      status: "error",
      message: "Login check failed",
      risk_score: 9,
      environment: "production",
    });
  });

  it("should throw error if ip_address is missing", async () => {
    await expect(
      loginLlama.checkLogin({
        user_agent: "Mozilla/5.0",
        identity_key: "validUser",
      })
    ).rejects.toThrow("ip_address is required");
  });

  it("should throw error if user_agent is missing", async () => {
    await expect(
      loginLlama.checkLogin({
        ip_address: "192.168.1.1",
        identity_key: "validUser",
      })
    ).rejects.toThrow("user_agent is required");
  });

  it("should throw error if identity_key is missing", async () => {
    await expect(
      loginLlama.checkLogin({
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
        identity_key: undefined as any,
      })
    ).rejects.toThrow("identity_key is required");
  });

  it("should extract ip_address and user_agent from request object", async () => {
    const req = mockRequest("192.168.1.1", "Mozilla/5.0");

    const result = await loginLlama.check_login({
      request: req as Request,
      identity_key: "validUser",
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
