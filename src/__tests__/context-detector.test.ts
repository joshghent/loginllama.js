import { ContextDetector } from "../context-detector";
import { AsyncLocalStorage } from "async_hooks";

// Mock IPExtractor
jest.mock("../ip-extractor", () => ({
  IPExtractor: {
    extract: jest.fn((request: any) => {
      if (request?.ip) return request.ip;
      if (request?.headers?.["x-forwarded-for"]) return request.headers["x-forwarded-for"];
      return undefined;
    }),
  },
}));

const mockExpressRequest = (ip: string, userAgent: string): any => {
  return {
    ip: ip,
    headers: {
      "user-agent": userAgent,
    },
    app: {
      _router: {},
    },
  };
};

const mockNextJsRequest = (ip: string, userAgent: string): any => {
  return {
    headers: {
      get: (key: string) => {
        if (key === "user-agent") return userAgent;
        return null;
      },
    },
    nextUrl: "https://example.com/path",
  };
};

const mockUnknownRequest = (ip: string, userAgent: string): any => {
  return {
    ip: ip,
    headers: {
      "user-agent": userAgent,
    },
  };
};

describe("ContextDetector", () => {
  beforeEach(() => {
    ContextDetector.clearContext();
  });

  describe("setContext and getContext", () => {
    it("should set and retrieve context for Express request", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(req);
    });

    it("should set and retrieve context for Next.js request", () => {
      const req = mockNextJsRequest("10.0.0.1", "Chrome/91.0");
      
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.userAgent).toBe("Chrome/91.0");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(req);
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
    });

    it("should handle undefined request", () => {
      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
    });
  });

  describe("framework detection", () => {
    it("should detect Express framework", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "user-agent": "Mozilla/5.0" },
        app: { _router: {} },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const req = {
        nextUrl: "https://example.com",
        headers: {
          get: () => "Mozilla/5.0",
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized framework", () => {
      const req = mockUnknownRequest("192.168.1.1", "Mozilla/5.0");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });

    it("should prioritize Express detection over unknown", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "user-agent": "Mozilla/5.0" },
        app: { _router: {} },
        someOtherProp: true,
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });
  });

  describe("User-Agent extraction", () => {
    it("should extract user-agent from Express headers (lowercase)", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "user-agent": "Mozilla/5.0" },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should extract user-agent from Express headers (uppercase)", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "User-Agent": "Chrome/91.0" },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Chrome/91.0");
    });

    it("should extract user-agent from Next.js headers.get()", () => {
      const req = mockNextJsRequest("10.0.0.1", "Safari/14.0");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Safari/14.0");
    });

    it("should handle array user-agent values", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "user-agent": ["Mozilla/5.0", "Chrome/91.0"] },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should return undefined when user-agent is missing from Express", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {},
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when user-agent is missing from Next.js", () => {
      const req = {
        nextUrl: "https://example.com",
        headers: {
          get: () => null,
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when headers object is missing", () => {
      const req = {
        ip: "192.168.1.1",
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });
  });

  describe("async context isolation", () => {
    it("should maintain separate contexts in different async scopes", async () => {
      const req1 = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      const req2 = mockExpressRequest("10.0.0.1", "Chrome/91.0");

      const promise1 = new Promise<void>((resolve) => {
        ContextDetector.setContext(req1);
        setTimeout(() => {
          const context = ContextDetector.getContext();
          expect(context?.ipAddress).toBe("192.168.1.1");
          expect(context?.userAgent).toBe("Mozilla/5.0");
          resolve();
        }, 10);
      });

      const promise2 = new Promise<void>((resolve) => {
        ContextDetector.setContext(req2);
        setTimeout(() => {
          const context = ContextDetector.getContext();
          expect(context?.ipAddress).toBe("10.0.0.1");
          expect(context?.userAgent).toBe("Chrome/91.0");
          resolve();
        }, 5);
      });

      await Promise.all([promise1, promise2]);
    });
  });

  describe("clearContext", () => {
    it("should exist as a method", () => {
      expect(typeof ContextDetector.clearContext).toBe("function");
    });

    it("should be callable without errors", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      ContextDetector.setContext(req);
      
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("edge cases", () => {
    it("should handle request with empty headers object", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {},
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should handle request with null headers", () => {
      const req = {
        ip: "192.168.1.1",
        headers: null,
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should overwrite context when setContext is called multiple times", () => {
      const req1 = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      const req2 = mockExpressRequest("10.0.0.1", "Chrome/91.0");

      ContextDetector.setContext(req1);
      ContextDetector.setContext(req2);

      const context = ContextDetector.getContext();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Chrome/91.0");
    });

    it("should handle request with both Express and Next.js properties", () => {
      const req = {
        ip: "192.168.1.1",
        headers: { "user-agent": "Mozilla/5.0" },
        app: { _router: {} },
        nextUrl: "https://example.com",
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      // Express should take priority based on detection order
      expect(context?.framework).toBe("express");
    });
  });
});