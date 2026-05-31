import Api from "../api";
import { LoginCheckStatus } from "../loginllama";
import type { JsonApiResponse } from "../types";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const mockBaseUrl = "https://api.example.com";
  const mockHeaders = { Authorization: "Bearer test-token" };

  beforeEach(() => {
    api = new Api(mockHeaders, mockBaseUrl);
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("should set default headers correctly", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe("Bearer test-token");
    });

    it("should set baseUrl correctly", () => {
      expect(api.baseUrl).toBe(mockBaseUrl);
    });

    it("should merge custom headers with defaults", () => {
      const customApi = new Api(
        {
          "Custom-Header": "custom-value",
          Authorization: "Bearer custom-token",
        },
        mockBaseUrl
      );

      expect(customApi.headers.get("Custom-Header")).toBe("custom-value");
      expect(customApi.headers.get("Authorization")).toBe("Bearer custom-token");
      expect(customApi.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
    });
  });

  describe("get", () => {
    it("should make GET request with correct URL and headers", async () => {
      const mockResponse = { data: "test" };
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockResponse),
      });

      const result = await api.get("/test-endpoint");

      expect(fetch).toHaveBeenCalledWith(`${mockBaseUrl}/test-endpoint`, {
        method: "GET",
        headers: api.headers,
      });
      expect(result).toEqual(mockResponse);
    });

    it("should throw error when response is not ok", async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/not-found")).rejects.toThrow("404: Not Found");
    });

    it("should throw error for 500 status", async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/error")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should throw error for 401 status", async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
      });

      await expect(api.get("/unauthorized")).rejects.toThrow("401: Unauthorized");
    });
  });

  describe("post", () => {
    it("should make POST request with correct parameters", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
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

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const params = {
        identity_key: "test-user",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
      };

      const result = await api.post("/login-check", params);

      expect(fetch).toHaveBeenCalledWith(`${mockBaseUrl}/login-check`, {
        method: "POST",
        body: JSON.stringify(params),
        headers: api.headers,
      });

      expect(result.status).toBe("success");
      expect(result.codes).toContain(LoginCheckStatus.VALID);
      expect(result.risk_score).toBe(2);
    });

    it("should make POST request without params", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "success",
            message: "OK",
            codes: [],
            risk_score: 0,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      await api.post("/endpoint");

      expect(fetch).toHaveBeenCalledWith(`${mockBaseUrl}/endpoint`, {
        method: "POST",
        body: JSON.stringify({}),
        headers: api.headers,
      });
    });

    it("should handle JSON:API error responses", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Bad Request",
            detail: "Invalid parameters",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check", {});

      expect(result.errors).toEqual([
        {
          status: "400",
          title: "Bad Request",
          detail: "Invalid parameters",
        },
      ]);
    });

    it("should throw error when response is not ok and no errors in body", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "error",
            message: "Failed",
            codes: [],
            risk_score: 0,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      await expect(api.post("/endpoint")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should transform JSON:API response to flat format", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "456",
          attributes: {
            status: "error",
            message: "Suspicious login",
            codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
            risk_score: 9,
            environment: "production",
            unrecognized_device: true,
            email_sent: true,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check");

      expect(result.status).toBe("error");
      expect(result.message).toBe("Suspicious login");
      expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
      expect(result.risk_score).toBe(9);
      expect(result.environment).toBe("production");
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });

    it("should handle multiple error objects in JSON:API response", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Bad Request",
            detail: "Missing identity_key",
          },
          {
            status: "400",
            title: "Bad Request",
            detail: "Missing ip_address",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: jest.fn().mockResolvedValueOnce(mockJsonApiResponse),
      });

      const result = await api.post("/login-check");

      expect(result.errors).toHaveLength(2);
      expect(result.errors![0].detail).toBe("Missing identity_key");
      expect(result.errors![1].detail).toBe("Missing ip_address");
    });
  });
});