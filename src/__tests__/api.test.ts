import Api from "../api";
import { LoginCheckStatus } from "../loginllama";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const mockBaseUrl = "https://api.example.com";
  const mockApiKey = "test-api-key";

  beforeEach(() => {
    api = new Api({ Authorization: `Bearer ${mockApiKey}` }, mockBaseUrl);
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("should initialize with default headers and custom headers", () => {
      const customHeaders = { Authorization: `Bearer ${mockApiKey}` };
      const api = new Api(customHeaders, mockBaseUrl);

      expect(api.baseUrl).toBe(mockBaseUrl);
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe(`Bearer ${mockApiKey}`);
    });

    it("should merge custom headers with default headers", () => {
      const customHeaders = {
        Authorization: `Bearer ${mockApiKey}`,
        "X-Custom-Header": "custom-value",
      };
      const api = new Api(customHeaders, mockBaseUrl);

      expect(api.headers.get("X-Custom-Header")).toBe("custom-value");
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
    });
  });

  describe("get", () => {
    it("should make a successful GET request", async () => {
      const mockData = { data: "test" };
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockData,
      });

      const result = await api.get("/test-endpoint");

      expect(global.fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/test-endpoint`,
        {
          method: "GET",
          headers: api.headers,
        }
      );
      expect(result).toEqual(mockData);
    });

    it("should throw error when response is not ok", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/not-found")).rejects.toThrow("404: Not Found");
    });

    it("should throw error for server error", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/error")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should throw error for unauthorized request", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      });

      await expect(api.get("/unauthorized")).rejects.toThrow(
        "401: Unauthorized"
      );
    });
  });

  describe("post", () => {
    it("should make a successful POST request with transformed response", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            message: "Login check passed",
            codes: [LoginCheckStatus.VALID],
            risk_score: 2,
            environment: "staging",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const params = {
        identity_key: "user123",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
      };

      const result = await api.post("/login-check", params);

      expect(global.fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/login-check`,
        {
          method: "POST",
          body: JSON.stringify(params),
          headers: api.headers,
        }
      );
      expect(result.status).toBe("success");
      expect(result.message).toBe("Login check passed");
      expect(result.codes).toContain(LoginCheckStatus.VALID);
      expect(result.risk_score).toBe(2);
    });

    it("should handle POST request with empty params", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            message: "Test",
            codes: [],
            risk_score: 0,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/test");

      expect(global.fetch).toHaveBeenCalledWith(`${mockBaseUrl}/test`, {
        method: "POST",
        body: JSON.stringify({}),
        headers: api.headers,
      });
      expect(result.status).toBe("success");
    });

    it("should handle response with errors array", async () => {
      const mockJsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Bad Request",
            detail: "Invalid parameters",
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/invalid");

      expect(result.errors).toBeDefined();
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].title).toBe("Bad Request");
    });

    it("should throw error when response is not ok and no errors in body", async () => {
      const mockJsonApiResponse = {
        data: null,
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => mockJsonApiResponse,
      });

      await expect(api.post("/error")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should handle suspicious login response", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "456",
          attributes: {
            status: "error",
            message: "Suspicious activity detected",
            codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
            risk_score: 9,
            environment: "production",
            unrecognized_device: true,
            email_sent: true,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", {
        identity_key: "suspicious_user",
      });

      expect(result.status).toBe("error");
      expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
      expect(result.risk_score).toBe(9);
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });

    it("should handle network errors", async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(
        new Error("Network error")
      );

      await expect(api.post("/test")).rejects.toThrow("Network error");
    });

    it("should handle JSON parsing errors", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => {
          throw new Error("Invalid JSON");
        },
      });

      await expect(api.post("/test")).rejects.toThrow("Invalid JSON");
    });

    it("should include all headers in POST request", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            codes: [],
            risk_score: 0,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      await api.post("/test", { test: "data" });

      const callArgs = (global.fetch as jest.Mock).mock.calls[0];
      expect(callArgs[1].headers).toBe(api.headers);
    });
  });
});