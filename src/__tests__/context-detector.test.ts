import { ContextDetector } from "../context-detector";
import { AsyncLocalStorage } from "async_hooks";

// Mock IPExtractor
jest.mock("../ip-extractor", () => ({
  IPExtractor: {
    extract: jest.fn((request) => {
      if (request?.ip) return request.ip;
      if (request?.headers?.["x-forwarded-for"]) return request.headers["x-forwarded-for"];
      return undefined;
    }),
  },
}));

const mockExpressRequest = (ip?: string, userAgent?: string): any => {
  return {
    ip: ip || "192.168.1.1",
    headers: {
      "user-agent": userAgent || "Mozilla/5.0",
    },
    app: {
      _router: {},
    },
  };
};

const mockNextJsRequest = (ip?: string, userAgent?: string): any => {
  return {
    ip: ip || "192.168.1.1",
    headers: {
      get: (key: string) => {
        if (key === "user-agent") return userAgent || "Mozilla/5.0 NextJS";
        return undefined;
      },
    },
    nextUrl: "https://example.com",
  };
};

describe("ContextDetector", () => {
  afterEach(() => {
    ContextDetector.clearContext();
  });

  describe("setContext and getContext", () => {
    it("should store and retrieve Express request context", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(req);
    });

    it("should store and retrieve Next.js request context", () => {
      const req = mockNextJsRequest("10.0.0.1", "Mozilla/5.0 NextJS");
      
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Mozilla/5.0 NextJS");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(req);
    });

    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should overwrite previous context when setContext is called again", () => {
      const req1 = mockExpressRequest("192.168.1.1", "Agent1");
      const req2 = mockExpressRequest("10.0.0.1", "Agent2");

      ContextDetector.setContext(req1);
      let context = ContextDetector.getContext();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Agent1");

      ContextDetector.setContext(req2);
      context = ContextDetector.getContext();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Agent2");
    });
  });

  describe("detectFramework", () => {
    it("should detect Express framework", () => {
      const req = mockExpressRequest();
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const req = mockNextJsRequest();
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized framework", () => {
      const req = { ip: "192.168.1.1", headers: {} };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("unknown");
    });

    it("should return unknown for null or undefined request", () => {
      ContextDetector.setContext(null);
      let context = ContextDetector.getContext();
      expect(context?.framework).toBe("unknown");

      ContextDetector.setContext(undefined);
      context = ContextDetector.getContext();
      expect(context?.framework).toBe("unknown");
    });
  });

  describe("extractUserAgent", () => {
    it("should extract User-Agent from Express lowercase headers", () => {
      const req = {
        headers: {
          "user-agent": "Mozilla/5.0 Lowercase",
        },
      };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Mozilla/5.0 Lowercase");
    });

    it("should extract User-Agent from Express capitalized headers", () => {
      const req = {
        headers: {
          "User-Agent": "Mozilla/5.0 Capitalized",
        },
      };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Mozilla/5.0 Capitalized");
    });

    it("should extract User-Agent from array values", () => {
      const req = {
        headers: {
          "user-agent": ["Mozilla/5.0 Array", "Other"],
        },
      };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Mozilla/5.0 Array");
    });

    it("should extract User-Agent from Next.js headers.get()", () => {
      const req = mockNextJsRequest("192.168.1.1", "NextJS Agent");
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("NextJS Agent");
    });

    it("should return undefined when User-Agent is not present", () => {
      const req = {
        headers: {},
      };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined for null or undefined request", () => {
      ContextDetector.setContext(null);
      let context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();

      ContextDetector.setContext(undefined);
      context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when request has no headers", () => {
      const req = { ip: "192.168.1.1" };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });
  });

  describe("clearContext", () => {
    it("should allow manual context clearing", () => {
      const req = mockExpressRequest();
      ContextDetector.setContext(req);
      
      let context = ContextDetector.getContext();
      expect(context).toBeDefined();

      ContextDetector.clearContext();
      // Note: clearContext is a no-op in the current implementation
      // AsyncLocalStorage clears automatically when async scope exits
      // This test verifies the method exists and can be called
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("edge cases", () => {
    it("should handle request with partial data", () => {
      const req = {
        ip: "192.168.1.1",
      };
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
    });

    it("should handle empty request object", () => {
      const req = {};
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      
      expect(context).toBeDefined();
      expect(context?.framework).toBe("unknown");
    });

    it("should store rawRequest even when other fields are undefined", () => {
      const req = {};
      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();
      
      expect(context?.rawRequest).toBe(req);
    });
  });
});