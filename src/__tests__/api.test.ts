Looking at the source file, I need to check the `types.ts` file's `transformApiResponse` behavior, but since I don't have direct access to it, I'll infer its behavior based on usage patterns in the source and the reference test file (which shows the expected flat response shape with `status`, `message`, `codes`, `risk_score`, `environment`, `unrecognized_device`, `email_sent`).

```typescript
import Api from "../api";

describe("Api", () => {
  const baseUrl = "https://api.example.com";
  let api: Api;

  beforeEach(() => {
    api = new Api({ Authorization: "Bearer mockToken" }, baseUrl);
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe("constructor", () => {
    it("should set default headers merged with provided headers", () => {
      expect(api.headers.get("X-LOGINLLAMA-SOURCE")).toBe("node-sdk");
      expect(api.headers.get("X-LOGINLLAMA-VERSION")).toBe("2");
      expect(api.headers.get("Content-Type")).toBe("application/json");
      expect(api.headers.get("Authorization")).toBe("Bearer mockToken");
    });

    it("should allow overriding default headers", () => {
      const customApi = new Api(
        { "Content-Type": "text/plain" },
        baseUrl
      );
      expect(customApi.headers.get("Content-Type")).toBe("text/plain");
    });

    it("should set the base URL", () => {
      expect(api.baseUrl).toBe(baseUrl);
    });
  });

  describe("get", () => {
    it("should make a GET request to the correct URL with headers", async () => {
      const mockJson = { data: "some data" };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: jest.fn().mockResolvedValue(mockJson),
      });

      const result = await api.get("/test-endpoint");

      expect(global.fetch).toHaveBeenCalledWith(
        `${baseUrl}/test-endpoint`,
        expect.objectContaining({
          method: "GET",
          headers: api.headers,
        })
      );
      expect(result).toEqual(mockJson);
    });

    it("should throw an error when response is not ok", async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        json: jest.fn().mockResolvedValue({}),
      });

      await expect(api.get("/missing-endpoint")).rejects.toThrow(
        "404: Not Found"
      );
    });

    it("should throw an error for server errors", async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: jest.fn().mockResolvedValue({}),
      });

      await expect(api.get("/error-endpoint")).rejects.toThrow(
        "500: Internal Server Error"
      );
    });
  });

  describe("post", () => {
    it("should make a POST request with JSON stringified body", async () => {
      const params = { identity_key: "user123" };
      const jsonApiResponse = {
        data: {
          type: "login_check",
          attributes: {
            status: "success",
            message: "Login check passed",
            codes: ["VALID"],
            risk_score: 1,
            environment: "production",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      await api.post("/login-check", params);

      expect(global.fetch).toHaveBeenCalledWith(
        `${baseUrl}/login-check`,
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(params),
          headers: api.headers,
        })
      );
    });

    it("should default params to an empty object when not provided", async () => {
      const jsonApiResponse = {
        data: {
          type: "login_check",
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

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      await api.post("/no-params-endpoint");

      expect(global.fetch).toHaveBeenCalledWith(
        `${baseUrl}/no-params-endpoint`,
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({}),
          headers: api.headers,
        })
      );
    });

    it("should return transformed response on success", async () => {
      const jsonApiResponse = {
        data: {
          type: "login_check",
          attributes: {
            status: "success",
            message: "Login check passed",
            codes: ["VALID"],
            risk_score: 2,
            environment: "staging",
            unrecognized_device: false,
            email_sent: false,
          },
        },
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      const result = await api.post("/login-check", { identity_key: "abc" });

      expect(result.status).toBe("success");
      expect(result.message).toBe("Login check passed");
      expect(result.codes).toContain("VALID");
      expect(result.risk_score).toBe(2);
      expect(result.environment).toBe("staging");
      expect(result.unrecognized_device).toBe(false);
      expect(result.email_sent).toBe(false);
    });

    it("should throw an error when response is not ok and there are no errors in body", async () => {
      const jsonApiResponse = {
        data: null,
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      await expect(
        api.post("/login-check", { identity_key: "abc" })
      ).rejects.toThrow("500: Internal Server Error");
    });

    it("should not throw when response is not ok but errors are present in body", async () => {
      const jsonApiResponse = {
        errors: [
          {
            status: "422",
            title: "Validation Error",
            detail: "identity_key is required",
          },
        ],
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 422,
        statusText: "Unprocessable Entity",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      const result = await api.post("/login-check", {});
      expect(result).toBeDefined();
    });

    it("should handle empty errors array as no errors present in strict check", async () => {
      const jsonApiResponse = {
        errors: [],
        data: null,
      };

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      // An empty array is truthy, so this should not throw
      const result = await api.post("/login-check", {});
      expect(result).toBeDefined();
    });

    it("should call fetch only once per post call", async () => {
      const jsonApiResponse = {
        data: {
          type: "login_check",
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

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: jest.fn().mockResolvedValue(jsonApiResponse),
      });

      await api.post("/login-check", { identity_key: "abc" });

      expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });
});