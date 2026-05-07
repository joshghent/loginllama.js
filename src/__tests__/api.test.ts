import Api from "../api";
import { LoginCheckStatus } from "../loginllama";
import { JsonApiResponse } from "../types";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const mockBaseUrl = "https://api.example.com";
  const mockHeaders = {
    Authorization: "Bearer test-token",
  };

  beforeEach(() => {
    api = new Api(mockHeaders, mockBaseUrl);
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("should initialize with default headers and custom headers", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe("Bearer test-token");
    });

    it("should set the base URL", () => {
      expect(api.baseUrl).toBe(mockBaseUrl);
    });
  });

  describe("get", () => {
    it("should make a GET request and return JSON response", async () => {
      const mockResponse = { data: "test" };
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await api.get("/test-endpoint");

      expect(fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/test-endpoint`,
        {
          method: "GET",
          headers: api.headers,
        }
      );
      expect(result).toEqual(mockResponse);
    });

    it("should throw an error if response is not ok", async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/test-endpoint")).rejects.toThrow(
        "404: Not Found"
      );
    });

    it("should throw an error on 500 status", async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/test-endpoint")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });
  });

  describe("post", () => {
    it("should make a POST request and return transformed response", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          id: "123",
          type: "login_check",
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
        json: async () => mockJsonApiResponse,
      });

      const params = {
        identity_key: "user123",
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0",
      };

      const result = await api.post("/login/check", params);

      expect(fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/login/check`,
        {
          method: "POST",
          body: JSON.stringify(params),
          headers: api.headers,
        }
      );
      expect(result.status).toBe("success");
      expect(result.message).toBe("Login check passed");
      expect(result.codes).toEqual([LoginCheckStatus.VALID]);
      expect(result.risk_score).toBe(2);
      expect(result.environment).toBe("staging");
      expect(result.unrecognized_device).toBe(false);
      expect(result.email_sent).toBe(false);
    });

    it("should handle POST request with no params", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          id: "123",
          type: "login_check",
          attributes: {
            status: "success",
            message: "Login check passed",
            codes: [LoginCheckStatus.VALID],
            risk_score: 1,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/test-endpoint");

      expect(fetch).toHaveBeenCalledWith(
        `${mockBaseUrl}/test-endpoint`,
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: api.headers,
        }
      );
      expect(result.status).toBe("success");
    });

    it("should return error response with validation errors from API", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "422",
            title: "Validation Error",
            detail: "identity_key is required",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 422,
        statusText: "Unprocessable Entity",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login/check", {});

      expect(result.status).toBe("error");
      expect(result.message).toBe("identity_key is required");
      expect(result.codes).toEqual([]);
    });

    it("should handle multiple validation errors", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "422",
            title: "Validation Error",
            detail: "identity_key is required",
          },
          {
            status: "422",
            title: "Validation Error",
            detail: "ip_address is required",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 422,
        statusText: "Unprocessable Entity",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login/check", {});

      expect(result.status).toBe("error");
      expect(result.message).toBe("identity_key is required; ip_address is required");
      expect(result.codes).toEqual([]);
    });

    it("should throw an error if response is not ok and no errors in body", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          id: "123",
          type: "login_check",
          attributes: {
            status: "error",
            message: "Something went wrong",
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
        json: async () => mockJsonApiResponse,
      });

      await expect(api.post("/login/check", {})).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should return transformed response for suspicious login", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          id: "456",
          type: "login_check",
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

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login/check", {
        identity_key: "malicious-user",
        ip_address: "123.45.67.89",
        user_agent: "BadBot/1.0",
      });

      expect(result.status).toBe("error");
      expect(result.message).toBe("Login check failed");
      expect(result.codes).toEqual([LoginCheckStatus.IP_ADDRESS_SUSPICIOUS]);
      expect(result.risk_score).toBe(9);
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });

    it("should handle response with multiple status codes", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          id: "789",
          type: "login_check",
          attributes: {
            status: "error",
            message: "Multiple issues detected",
            codes: [
              LoginCheckStatus.IP_ADDRESS_SUSPICIOUS,
              LoginCheckStatus.GEOLOCATION_MISMATCH,
            ],
            risk_score: 8,
            environment: "production",
            unrecognized_device: true,
            email_sent: true,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login/check", {
        identity_key: "user",
        ip_address: "1.2.3.4",
        user_agent: "Mozilla/5.0",
      });

      expect(result.codes).toHaveLength(2);
      expect(result.codes).toContain(LoginCheckStatus.IP_ADDRESS_SUSPICIOUS);
      expect(result.codes).toContain(LoginCheckStatus.GEOLOCATION_MISMATCH);
    });
  });
});