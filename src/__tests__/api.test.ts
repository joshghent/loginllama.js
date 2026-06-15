import Api from "../api";
import { LoginCheckStatus } from "../loginllama";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const baseUrl = "https://api.example.com";
  const mockHeaders = { Authorization: "Bearer token123" };

  beforeEach(() => {
    api = new Api(mockHeaders, baseUrl);
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("should initialize with correct headers", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe("Bearer token123");
    });

    it("should initialize with correct base URL", () => {
      expect(api.baseUrl).toBe(baseUrl);
    });

    it("should merge default headers with custom headers", () => {
      const customApi = new Api(
        { Authorization: "Bearer custom", "X-Custom": "value" },
        baseUrl
      );
      expect(customApi.headers.get("Authorization")).toBe("Bearer custom");
      expect(customApi.headers.get("X-Custom")).toBe("value");
      expect(customApi.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
    });
  });

  describe("get", () => {
    it("should make GET request with correct URL and headers", async () => {
      const mockResponse = { data: "test" };
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await api.get("/test-endpoint");

      expect(global.fetch).toHaveBeenCalledWith(
        `${baseUrl}/test-endpoint`,
        {
          method: "GET",
          headers: api.headers,
        }
      );
      expect(result).toEqual(mockResponse);
    });

    it("should throw error when response is not ok", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/missing")).rejects.toThrow("404: Not Found");
    });

    it("should throw error for 500 status code", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/error")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should handle network errors", async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(
        new Error("Network error")
      );

      await expect(api.get("/network-error")).rejects.toThrow("Network error");
    });
  });

  describe("post", () => {
    it("should make POST request with correct URL, headers, and body", async () => {
      const params = { identity_key: "user123" };
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

      const result = await api.post("/login-check", params);

      expect(global.fetch).toHaveBeenCalledWith(`${baseUrl}/login-check`, {
        method: "POST",
        body: JSON.stringify(params),
        headers: api.headers,
      });

      expect(result.status).toBe("success");
      expect(result.message).toBe("Login check passed");
      expect(result.codes).toContain(LoginCheckStatus.VALID);
      expect(result.risk_score).toBe(2);
    });

    it("should handle POST request without params", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            message: "OK",
            codes: [],
            risk_score: 0,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      await api.post("/endpoint");

      expect(global.fetch).toHaveBeenCalledWith(`${baseUrl}/endpoint`, {
        method: "POST",
        body: JSON.stringify({}),
        headers: api.headers,
      });
    });

    it("should transform JSON:API response to flat format", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "456",
          attributes: {
            status: "error",
            message: "Suspicious activity",
            codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
            risk_score: 8,
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

      const result = await api.post("/check");

      expect(result).toEqual({
        status: "error",
        message: "Suspicious activity",
        codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
        risk_score: 8,
        environment: "production",
        unrecognized_device: true,
        email_sent: true,
      });
    });

    it("should handle JSON:API error response", async () => {
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

      expect(result.errors).toEqual(mockJsonApiResponse.errors);
    });

    it("should throw error when response is not ok and no errors in body", async () => {
      const mockJsonApiResponse = {
        data: {
          type: "login_check",
          id: "789",
          attributes: {},
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => mockJsonApiResponse,
      });

      await expect(api.post("/error-endpoint")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should not throw error when response is not ok but has errors in body", async () => {
      const mockJsonApiResponse = {
        errors: [
          {
            status: "422",
            title: "Validation Error",
            detail: "Missing required field",
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 422,
        statusText: "Unprocessable Entity",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/validation-error");

      expect(result.errors).toEqual(mockJsonApiResponse.errors);
    });

    it("should handle network errors during POST", async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(
        new Error("Connection refused")
      );

      await expect(api.post("/network-fail")).rejects.toThrow(
        "Connection refused"
      );
    });

    it("should handle multiple error objects in response", async () => {
      const mockJsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Error 1",
            detail: "Detail 1",
          },
          {
            status: "400",
            title: "Error 2",
            detail: "Detail 2",
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/multiple-errors");

      expect(result.errors).toHaveLength(2);
      expect(result.errors?.[0].title).toBe("Error 1");
      expect(result.errors?.[1].title).toBe("Error 2");
    });
  });
});