import Api from "../api";
import { LoginCheckStatus } from "../loginllama";
import type { JsonApiResponse } from "../types";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const baseUrl = "https://api.example.com";
  const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

  beforeEach(() => {
    api = new Api({ Authorization: "Bearer test-token" }, baseUrl);
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
      expect(api.baseUrl).toBe(baseUrl);
    });

    it("should merge custom headers with defaults", () => {
      const customApi = new Api(
        {
          Authorization: "Bearer custom-token",
          "X-Custom-Header": "custom-value",
        },
        baseUrl
      );

      expect(customApi.headers.get("Authorization")).toBe("Bearer custom-token");
      expect(customApi.headers.get("X-Custom-Header")).toBe("custom-value");
      expect(customApi.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
    });
  });

  describe("get", () => {
    it("should make a GET request with correct headers", async () => {
      const mockResponse = { data: "test" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        status: 200,
        statusText: "OK",
      } as Response);

      const result = await api.get("/test-endpoint");

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test-endpoint`, {
        method: "GET",
        headers: api.headers,
      });
      expect(result).toEqual(mockResponse);
    });

    it("should throw error on non-ok response", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      } as Response);

      await expect(api.get("/not-found")).rejects.toThrow("404: Not Found");
    });

    it("should throw error on server error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      } as Response);

      await expect(api.get("/error")).rejects.toThrow("500: Internal Server Error");
    });

    it("should handle network errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      await expect(api.get("/test")).rejects.toThrow("Network error");
    });
  });

  describe("post", () => {
    it("should make a POST request with correct headers and body", async () => {
      const params = { identity_key: "user123", ip_address: "192.168.1.1" };
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_attempt",
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

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
        status: 200,
        statusText: "OK",
      } as Response);

      const result = await api.post("/login/check", params);

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/login/check`, {
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
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_attempt",
          id: "123",
          attributes: {
            status: "success",
            message: "Login check passed",
            codes: [LoginCheckStatus.VALID],
            risk_score: 0,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
        status: 200,
        statusText: "OK",
      } as Response);

      await api.post("/test");

      expect(mockFetch).toHaveBeenCalledWith(`${baseUrl}/test`, {
        method: "POST",
        body: JSON.stringify({}),
        headers: api.headers,
      });
    });

    it("should return errors from JSON:API response", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Invalid Request",
            detail: "identity_key is required",
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => mockJsonApiResponse,
        status: 400,
        statusText: "Bad Request",
      } as Response);

      const result = await api.post("/login/check", {});

      expect(result.errors).toBeDefined();
      expect(result.errors).toHaveLength(1);
      expect(result.errors![0].detail).toBe("identity_key is required");
    });

    it("should throw error on non-ok response without error body", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_attempt",
          id: "123",
          attributes: {
            status: "error",
            message: "Unknown error",
            codes: [],
            risk_score: 0,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => mockJsonApiResponse,
        status: 500,
        statusText: "Internal Server Error",
      } as Response);

      await expect(api.post("/test")).rejects.toThrow("500: Internal Server Error");
    });

    it("should handle network errors in POST", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      await expect(api.post("/test", {})).rejects.toThrow("Network error");
    });

    it("should transform JSON:API response with multiple errors", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Validation Error",
            detail: "ip_address is invalid",
          },
          {
            status: "400",
            title: "Validation Error",
            detail: "user_agent is required",
          },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => mockJsonApiResponse,
        status: 400,
        statusText: "Bad Request",
      } as Response);

      const result = await api.post("/login/check", {});

      expect(result.errors).toHaveLength(2);
      expect(result.errors![0].detail).toBe("ip_address is invalid");
      expect(result.errors![1].detail).toBe("user_agent is required");
    });

    it("should handle suspicious login response", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_attempt",
          id: "456",
          attributes: {
            status: "error",
            message: "Suspicious login detected",
            codes: [LoginCheckStatus.IP_ADDRESS_SUSPICIOUS],
            risk_score: 9,
            environment: "production",
            unrecognized_device: true,
            email_sent: true,
          },
        },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
        status: 200,
        statusText: "OK",
      } as Response);

      const result = await api.post("/login/check", {
        identity_key: "user123",
        ip_address: "1.2.3.4",
      });

      expect(result.status).toBe("error");
      expect(result.message).toBe("Suspicious login detected");
      expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
      expect(result.risk_score).toBe(9);
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });
  });
});