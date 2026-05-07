import { ContextDetector } from "../context-detector";
import type { RequestContext } from "../context-detector";

// Mock IPExtractor
jest.mock("../ip-extractor", () => ({
  IPExtractor: {
    extract: jest.fn((request: any) => {
      if (request?.ip) return request.ip;
      if (request?.socket?.remoteAddress) return request.socket.remoteAddress;
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
    ip: ip,
    headers: {
      get: (key: string) => {
        if (key === "user-agent") return userAgent;
        return null;
      },
    },
    nextUrl: "https://example.com",
  };
};

describe("ContextDetector", () => {
  afterEach(() => {
    ContextDetector.clearContext();
  });

  describe("setContext", () => {
    it("should store Express request context", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(req);
    });

    it("should store Next.js request context", () => {
      const req = mockNextJsRequest("10.0.0.1", "Chrome/90.0");
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Chrome/90.0");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(req);
    });

    it("should handle unknown framework", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context).toBeDefined();
      expect(context?.framework).toBe("unknown");
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

  describe("getContext", () => {
    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should return stored context", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
    });
  });

  describe("clearContext", () => {
    it("should be callable without errors", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      ContextDetector.setContext(req);

      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("detectFramework", () => {
    it("should detect Express by app._router", () => {
      const req = {
        app: {
          _router: {},
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js by nextUrl", () => {
      const req = {
        nextUrl: "https://example.com",
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("nextjs");
    });

    it("should prioritize Express detection over Next.js", () => {
      const req = {
        app: {
          _router: {},
        },
        nextUrl: "https://example.com",
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("express");
    });

    it("should return unknown for empty request object", () => {
      ContextDetector.setContext({});

      const context = ContextDetector.getContext();
      expect(context?.framework).toBe("unknown");
    });
  });

  describe("extractUserAgent", () => {
    it("should extract lowercase user-agent header from Express", () => {
      const req = {
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should extract uppercase User-Agent header from Express", () => {
      const req = {
        headers: {
          "User-Agent": "Chrome/90.0",
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Chrome/90.0");
    });

    it("should extract first value from array user-agent", () => {
      const req = {
        headers: {
          "user-agent": ["Mozilla/5.0", "Chrome/90.0"],
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should extract user-agent using get() method for Next.js", () => {
      const req = mockNextJsRequest("10.0.0.1", "Safari/14.0");
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBe("Safari/14.0");
    });

    it("should return undefined when headers.get() returns null", () => {
      const req = {
        headers: {
          get: () => null,
        },
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when headers are missing", () => {
      const req = {};
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when request is null", () => {
      ContextDetector.setContext(null);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });

    it("should handle empty headers object", () => {
      const req = {
        headers: {},
      };
      ContextDetector.setContext(req);

      const context = ContextDetector.getContext();
      expect(context?.userAgent).toBeUndefined();
    });
  });

  describe("async context isolation", () => {
    it("should maintain separate contexts in different async scopes", async () => {
      const req1 = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      const req2 = mockExpressRequest("10.0.0.1", "Chrome/90.0");

      const promise1 = new Promise<RequestContext | undefined>((resolve) => {
        ContextDetector.setContext(req1);
        setTimeout(() => {
          resolve(ContextDetector.getContext());
        }, 10);
      });

      const promise2 = new Promise<RequestContext | undefined>((resolve) => {
        ContextDetector.setContext(req2);
        setTimeout(() => {
          resolve(ContextDetector.getContext());
        }, 5);
      });

      const [context1, context2] = await Promise.all([promise1, promise2]);

      expect(context1?.ipAddress).toBe("192.168.1.1");
      expect(context1?.userAgent).toBe("Mozilla/5.0");
      expect(context2?.ipAddress).toBe("10.0.0.1");
      expect(context2?.userAgent).toBe("Chrome/90.0");
    });
  });
});