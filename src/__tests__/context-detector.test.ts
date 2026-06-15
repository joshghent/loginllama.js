import { ContextDetector } from "../context-detector";
import type { Request } from "express";

describe("ContextDetector", () => {
  beforeEach(() => {
    ContextDetector.clearContext();
  });

  afterEach(() => {
    ContextDetector.clearContext();
  });

  describe("setContext and getContext", () => {
    it("should store and retrieve Express request context", () => {
      const mockExpressRequest: Partial<Request> = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0 Express",
        } as any,
        app: {
          _router: {},
        } as any,
      };

      ContextDetector.setContext(mockExpressRequest);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0 Express");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(mockExpressRequest);
    });

    it("should store and retrieve Next.js request context", () => {
      const mockNextRequest = {
        ip: "10.0.0.1",
        nextUrl: "https://example.com",
        headers: {
          get: jest.fn((header: string) => {
            if (header === "user-agent") return "Mozilla/5.0 Next.js";
            return null;
          }),
        },
      };

      ContextDetector.setContext(mockNextRequest);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.userAgent).toBe("Mozilla/5.0 Next.js");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(mockNextRequest);
    });

    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should handle null request", () => {
      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBeNull();
    });

    it("should handle undefined request", () => {
      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBeUndefined();
    });
  });

  describe("framework detection", () => {
    it("should detect Express framework", () => {
      const mockExpressRequest = {
        app: {
          _router: {},
        },
        headers: {},
      };

      ContextDetector.setContext(mockExpressRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const mockNextRequest = {
        nextUrl: "https://example.com",
        headers: {
          get: jest.fn(),
        },
      };

      ContextDetector.setContext(mockNextRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized framework", () => {
      const mockGenericRequest = {
        headers: {
          "user-agent": "Generic",
        },
      };

      ContextDetector.setContext(mockGenericRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });

    it("should return unknown for empty object", () => {
      ContextDetector.setContext({});
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });
  });

  describe("user agent extraction", () => {
    it("should extract user-agent from Express headers (lowercase)", () => {
      const mockRequest = {
        headers: {
          "user-agent": "Mozilla/5.0 Lowercase",
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Lowercase");
    });

    it("should extract User-Agent from Express headers (uppercase)", () => {
      const mockRequest = {
        headers: {
          "User-Agent": "Mozilla/5.0 Uppercase",
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Uppercase");
    });

    it("should extract user-agent from array (first element)", () => {
      const mockRequest = {
        headers: {
          "user-agent": ["Mozilla/5.0 First", "Mozilla/5.0 Second"],
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 First");
    });

    it("should extract user-agent from Next.js headers.get()", () => {
      const mockRequest = {
        headers: {
          get: jest.fn((header: string) => {
            if (header === "user-agent") return "Mozilla/5.0 Next";
            return null;
          }),
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Next");
      expect(mockRequest.headers.get).toHaveBeenCalledWith("user-agent");
    });

    it("should return undefined when headers.get() returns null", () => {
      const mockRequest = {
        headers: {
          get: jest.fn(() => null),
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when no headers present", () => {
      const mockRequest = {};

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when headers is null", () => {
      const mockRequest = {
        headers: null,
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should handle empty headers object", () => {
      const mockRequest = {
        headers: {},
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });
  });

  describe("IP address extraction", () => {
    it("should extract IP from Express request", () => {
      const mockRequest: Partial<Request> = {
        ip: "203.0.113.42",
        headers: {} as any,
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBe("203.0.113.42");
    });

    it("should extract IP from x-forwarded-for header", () => {
      const mockRequest = {
        headers: {
          "x-forwarded-for": "198.51.100.1, 203.0.113.42",
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBe("198.51.100.1");
    });

    it("should extract IP from x-real-ip header", () => {
      const mockRequest = {
        headers: {
          "x-real-ip": "198.51.100.50",
        },
      };

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBe("198.51.100.50");
    });
  });

  describe("clearContext", () => {
    it("should not throw when clearing context", () => {
      const mockRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Test",
        },
      };

      ContextDetector.setContext(mockRequest);
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });

    it("should not throw when clearing non-existent context", () => {
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("async context isolation", () => {
    it("should maintain separate contexts in different async scopes", async () => {
      const request1 = {
        ip: "192.168.1.1",
        headers: { "user-agent": "User1" },
      };

      const request2 = {
        ip: "192.168.1.2",
        headers: { "user-agent": "User2" },
      };

      const promise1 = new Promise<void>((resolve) => {
        ContextDetector.setContext(request1);
        setTimeout(() => {
          const context = ContextDetector.getContext();
          expect(context?.ipAddress).toBe("192.168.1.1");
          expect(context?.userAgent).toBe("User1");
          resolve();
        }, 10);
      });

      const promise2 = new Promise<void>((resolve) => {
        ContextDetector.setContext(request2);
        setTimeout(() => {
          const context = ContextDetector.getContext();
          expect(context?.ipAddress).toBe("192.168.1.2");
          expect(context?.userAgent).toBe("User2");
          resolve();
        }, 5);
      });

      await Promise.all([promise1, promise2]);
    });
  });
});