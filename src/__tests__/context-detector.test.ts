import { ContextDetector } from "../context-detector";
import { IPExtractor } from "../ip-extractor";
import type { Request } from "express";

jest.mock("../ip-extractor");

const mockExpressRequest = (
  ip: string,
  userAgent: string
): Partial<Request> => {
  return {
    ip: ip,
    headers: {
      "user-agent": userAgent,
    } as any,
    app: {
      _router: {},
    } as any,
  } as Partial<Request>;
};

const mockNextJsRequest = (ip: string, userAgent: string): any => {
  return {
    ip: ip,
    headers: {
      get: (name: string) => {
        if (name === "user-agent") return userAgent;
        return undefined;
      },
    },
    nextUrl: "http://example.com/page",
  };
};

describe("ContextDetector", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");
  });

  afterEach(() => {
    ContextDetector.clearContext();
  });

  describe("setContext", () => {
    it("should store context for Express request", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(req);
    });

    it("should store context for Next.js request", () => {
      const req = mockNextJsRequest("10.0.0.1", "Chrome/90.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("10.0.0.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Chrome/90.0");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(req);
    });

    it("should handle null request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBeNull();
    });

    it("should handle undefined request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBeUndefined();
    });

    it("should call IPExtractor.extract with request", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");

      ContextDetector.setContext(req);

      expect(IPExtractor.extract).toHaveBeenCalledWith(req);
    });
  });

  describe("getContext", () => {
    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should return stored context", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
    });
  });

  describe("clearContext", () => {
    it("should not throw error when called", () => {
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });

    it("should be callable even when no context exists", () => {
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("detectFramework", () => {
    it("should detect Express framework", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const req = mockNextJsRequest("192.168.1.1", "Mozilla/5.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized request", () => {
      const req = { headers: { "user-agent": "Mozilla/5.0" } };
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });

    it("should return unknown for null request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });
  });

  describe("extractUserAgent", () => {
    it("should extract user-agent from Express request with lowercase header", () => {
      const req = mockExpressRequest("192.168.1.1", "Mozilla/5.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should extract User-Agent from Express request with capitalized header", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {
          "User-Agent": "Chrome/90.0",
        },
        app: { _router: {} },
      };
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Chrome/90.0");
    });

    it("should extract user-agent from Next.js request using headers.get()", () => {
      const req = mockNextJsRequest("192.168.1.1", "Safari/15.0");
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Safari/15.0");
    });

    it("should handle array value for user-agent header", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": ["Mozilla/5.0", "Chrome/90.0"],
        },
        app: { _router: {} },
      };
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should return undefined when user-agent header is missing", () => {
      const req = {
        ip: "192.168.1.1",
        headers: {},
        app: { _router: {} },
      };
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when request is null", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when request has no headers", () => {
      const req = { ip: "192.168.1.1" };
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });
  });
});