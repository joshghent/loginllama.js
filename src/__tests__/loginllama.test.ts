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
            });
          } else {
            return Promise.reject({
              status: "error",
              message: "Login check failed",
            });
          }
        }),
      };
    }),
  };
});

import { LoginLlama, LoginCheckStatus } from "../loginllama";

describe("LoginLlama", () => {
  let loginLlama: LoginLlama;

  beforeEach(() => {
    loginLlama = new LoginLlama("mockToken");
  });

  it("should check valid login", async () => {
    const result = await loginLlama.check_login({
      ip_address: "192.168.1.1",
      user_agent: "Mozilla/5.0",
      identity_key: "validUser",
    });

    expect(result.status).toBe("success");
    expect(result.message).toBe("Valid login");
    expect(result.codes).toContain(LoginCheckStatus.VALID);
  });

  it("should throw error for invalid login", async () => {
    await expect(
      loginLlama.check_login({
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
        identity_key: "invalidUser",
      })
    ).rejects.toEqual({
      status: "error",
      message: "Login check failed",
    });
  });

  it("should throw error if ip_address is missing", async () => {
    await expect(
      loginLlama.check_login({
        user_agent: "Mozilla/5.0",
        identity_key: "validUser",
      })
    ).rejects.toThrow("ip_address is required");
  });

  it("should throw error if user_agent is missing", async () => {
    await expect(
      loginLlama.check_login({
        ip_address: "192.168.1.1",
        identity_key: "validUser",
      })
    ).rejects.toThrow("user_agent is required");
  });

  it("should throw error if identity_key is missing", async () => {
    await expect(
      loginLlama.check_login({
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
        identity_key: undefined as any,
      })
    ).rejects.toThrow("identity_key is required");
  });
});
