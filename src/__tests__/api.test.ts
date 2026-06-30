import Api from "../api";
import { JsonApiResponse, LoginCheckResponse, LoginCheckStatus } from "../types";

// Mock fetch globally
global.fetch = jest.fn();

describe("Api", () => {
  let api: Api;
  const baseUrl = "https://api.example.com";
  const mockHeaders = {
    "Authorization": "Bearer test-token",
  };

  beforeEach(() => {
    api = new Api(mockHeaders, baseUrl);
    (fetch as jest.Mock).mockClear();
  });

  describe("constructor", () => {
    it("should initialize with default headers and custom headers", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe("Bearer test-token");
    });

    it("should set baseUrl", () => {
      expect(api.baseUrl).toBe(baseUrl);
    });
  });

  describe("get", () => {
    it("should make GET request with correct URL and headers", async () => {
      const mockResponse = { data: "test" };
      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await api.get("/test-endpoint");

      expect(fetch).toHaveBeenCalledWith(
        `${baseUrl}/test-endpoint`,
        {
          method: "GET",
          headers: api.headers,
        }
      );
      expect(result).toEqual(mockResponse);
    });

    it("should throw error when response is not ok", async () => {
      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(api.get("/test-endpoint")).rejects.toThrow("404: Not Found");
    });

    it("should throw error on 500 status", async () => {
      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(api.get("/test-endpoint")).rejects.toThrow("500: Internal Server Error");
    });
  });

  describe("post", () => {
    it("should make POST request with correct parameters", async () => {
      const params = { identity_key: "test-user", ip_address: "192.168.1.1" };
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
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

      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", params);

      expect(fetch).toHaveBeenCalledWith(
        `${baseUrl}/login-check`,
        {
          method: "POST",
          body: JSON.stringify(params),
          headers: api.headers,
        }
      );
      expect(result).toEqual({
        status: "success",
        message: "Login check passed",
        codes: [LoginCheckStatus.VALID],
        risk_score: 1,
        environment: "production",
        unrecognized_device: false,
        email_sent: false,
      });
    });

    it("should make POST request without parameters", async () => {
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

      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      await api.post("/endpoint");

      expect(fetch).toHaveBeenCalledWith(
        `${baseUrl}/endpoint`,
        {
          method: "POST",
          body: JSON.stringify({}),
          headers: api.headers,
        }
      );
    });

    it("should handle error response with errors in JSON", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "400",
            title: "Bad Request",
            detail: "Invalid parameters",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", {});

      expect(result).toEqual({
        errors: [
          {
            status: "400",
            title: "Bad Request",
            detail: "Invalid parameters",
          },
        ],
      });
    });

    it("should throw error when response is not ok and no errors in JSON", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "123",
          attributes: {
            status: "error",
            message: "Error",
            codes: [],
            risk_score: 0,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: async () => mockJsonApiResponse,
      });

      await expect(api.post("/login-check", {})).rejects.toThrow(
        "500: Internal Server Error"
      );
    });

    it("should handle response with multiple error codes", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "456",
          attributes: {
            status: "error",
            message: "Multiple issues detected",
            codes: [
              LoginCheckStatus.IP_ADDRESS_SUSPICIOUS,
              LoginCheckStatus.USER_AGENT_SUSPICIOUS,
            ],
            risk_score: 8,
            environment: "production",
            unrecognized_device: true,
            email_sent: true,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", {});

      expect(result.codes).toEqual([
        LoginCheckStatus.IP_ADDRESS_SUSPICIOUS,
        LoginCheckStatus.USER_AGENT_SUSPICIOUS,
      ]);
      expect(result.risk_score).toBe(8);
      expect(result.unrecognized_device).toBe(true);
      expect(result.email_sent).toBe(true);
    });

    it("should handle 401 unauthorized response with errors", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        errors: [
          {
            status: "401",
            title: "Unauthorized",
            detail: "Invalid API key",
          },
        ],
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", {});

      expect(result.errors).toHaveLength(1);
      expect(result.errors?.[0].status).toBe("401");
    });

    it("should handle response with empty codes array", async () => {
      const mockJsonApiResponse: JsonApiResponse = {
        data: {
          type: "login_check",
          id: "789",
          attributes: {
            status: "success",
            message: "No issues",
            codes: [],
            risk_score: 0,
            environment: "staging",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => mockJsonApiResponse,
      });

      const result = await api.post("/login-check", {});

      expect(result.codes).toEqual([]);
      expect(result.risk_score).toBe(0);
    });
  });
});