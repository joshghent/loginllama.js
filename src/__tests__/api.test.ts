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
    it("should initialize with default headers", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe(`Bearer ${mockApiKey}`);
    });

    it("should set baseUrl correctly", () => {
      expect(api.baseUrl).toBe(mockBaseUrl);
    });

    it("should merge custom headers with default headers", () => {
      const customApi = new Api(
        {
          Authorization: `Bearer ${mockApiKey}`,
          "Custom-Header": "custom-value",
        },
        mockBaseUrl
      );

      expect(customApi.headers.get("Custom-Header")).toBe("custom-value");
      expect(customApi.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
    });
  });

  describe("get", () => {
    it("should make a GET request and return JSON response", async () => {
      const mockResponseData = { data: "test" };
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponseData),
      });

      const result = await api.get("/test-endpoint");

      expect(global.fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/test-endpoint`,
        {
          method: "GET",
          headers: api.headers,
        }
      );
      expect(result).toEqual(mockResponseData);
    });

    it("should throw error when response is not ok", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/not-found")).rejects.toThrow("404: Not Found");
    });

    it("should throw error on 500 server error", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/server-error")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should throw error on 401 unauthorized", async () => {
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
    it("should make a POST request with params and return transformed response", async () => {
      const mockParams = {
        identity_key: "user123",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
      };

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
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check", mockParams);

      expect(global.fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/login-check`,
        {
          method: "POST",
          body: JSON.stringify(mockParams),
          headers: api.headers,
        }
      );
      expect(result.status).toBe("success");
      expect(result.message).toBe("Login check passed");
      expect(result.codes).toContain(LoginCheckStatus.VALID);
      expect(result.risk_score).toBe(2);
    });

    it("should make a POST request without params", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            message: "Default check",
            codes: [],
            risk_score: 0,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      await api.post("/login-check");

      expect(global.fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/login-check`,
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: api.headers,
        }
      );
    });

    it("should return errors from JSON:API error response", async () => {
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
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check", {});

      expect(result.errors).toEqual(mockJsonApiResponse.errors);
    });

    it("should throw error when response is not ok and no errors in body", async () => {
      const mockJsonApiResponse = {
        data: null,
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      await expect(api.post("/login-check", {})).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should handle suspicious login response", async () => {
      const mockParams = {
        identity_key: "suspicious_user",
        ip_address: "10.0.0.1",
        user_agent: "Suspicious Agent",
      };

      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "456",
          attributes: {
            status: "error",
            message: "Login check failed",
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
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check", mockParams);

      expect(result.status).toBe("error");
      expect(result.message).toBe("Login check failed");
      expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
      expect(result.risk_score).toBe(9);
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });

    it("should handle network errors", async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(
        new Error("Network error")
      );

      await expect(api.post("/login-check", {})).rejects.toThrow(
        "Network error"
      );
    });

    it("should handle JSON parsing errors gracefully", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockRejectedValueOnce(new Error("Invalid JSON")),
      });

      await expect(api.post("/login-check", {})).rejects.toThrow(
        "Invalid JSON"
      );
    });
  });
});