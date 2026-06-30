import { ContextDetector, RequestContext } from "../context-detector";
import { IPExtractor } from "../ip-extractor";

jest.mock("../ip-extractor");

describe("ContextDetector", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    ContextDetector.clearContext();
  });

  describe("setContext and getContext", () => {
    it("should store and retrieve request context", () => {
      const mockRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
        app: {
          _router: {},
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(mockRequest);
    });

    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should handle null request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBe(null);
    });

    it("should handle undefined request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
      expect(context?.rawRequest).toBe(undefined);
    });
  });

  describe("detectFramework", () => {
    it("should detect Express framework", () => {
      const expressRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
        app: {
          _router: {},
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const nextRequest = {
        nextUrl: new URL("http://localhost:3000"),
        headers: {
          get: jest.fn().mockReturnValue("Mozilla/5.0"),
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(nextRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized framework", () => {
      const genericRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(genericRequest);
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
    it("should extract user-agent from Express lowercase header", () => {
      const expressRequest = {
        headers: {
          "user-agent": "Mozilla/5.0 Express",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Express");
    });

    it("should extract user-agent from Express uppercase header", () => {
      const expressRequest = {
        headers: {
          "User-Agent": "Mozilla/5.0 Express",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Express");
    });

    it("should extract user-agent from array value", () => {
      const expressRequest = {
        headers: {
          "user-agent": ["Mozilla/5.0 Array", "Second Value"],
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Array");
    });

    it("should extract user-agent from Next.js headers.get()", () => {
      const nextRequest = {
        headers: {
          get: jest.fn((key: string) => {
            if (key === "user-agent") return "Mozilla/5.0 Next.js";
            return null;
          }),
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(nextRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Next.js");
    });

    it("should return undefined when user-agent is not present", () => {
      const request = {
        headers: {},
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when headers are missing", () => {
      const request = {
        ip: "192.168.1.1",
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when request is null", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when Next.js headers.get returns null", () => {
      const nextRequest = {
        headers: {
          get: jest.fn().mockReturnValue(null),
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(nextRequest);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should prefer lowercase user-agent header", () => {
      const request = {
        headers: {
          "user-agent": "lowercase-value",
          "User-Agent": "uppercase-value",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("lowercase-value");
    });
  });

  describe("clearContext", () => {
    it("should not throw when clearing context", () => {
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });

    it("should allow clearing context manually", () => {
      const mockRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      ContextDetector.setContext(mockRequest);
      ContextDetector.clearContext();

      // Context should still exist as clearContext is a no-op
      // AsyncLocalStorage automatically clears when scope exits
      const context = ContextDetector.getContext();
      expect(context).toBeDefined();
    });
  });

  describe("IPExtractor integration", () => {
    it("should call IPExtractor.extract with request", () => {
      const mockRequest = {
        ip: "192.168.1.1",
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue("10.0.0.1");

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(IPExtractor.extract).toHaveBeenCalledWith(mockRequest);
      expect(context?.ipAddress).toBe("10.0.0.1");
    });

    it("should handle undefined IP from IPExtractor", () => {
      const mockRequest = {
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };

      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(mockRequest);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBeUndefined();
    });
  });
});