import { ContextDetector, RequestContext } from "../context-detector";
import { IPExtractor } from "../ip-extractor";

jest.mock("../ip-extractor");

const mockIPExtractor = IPExtractor as jest.Mocked<typeof IPExtractor>;

describe("ContextDetector", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    ContextDetector.clearContext();
  });

  describe("setContext and getContext", () => {
    it("should store and retrieve Express request context", () => {
      const expressRequest = {
        app: { _router: {} },
        headers: {
          "user-agent": "Mozilla/5.0 (Express)",
        },
        ip: "192.168.1.1",
      };

      mockIPExtractor.extract.mockReturnValue("192.168.1.1");

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0 (Express)");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(expressRequest);
    });

    it("should store and retrieve Next.js request context", () => {
      const nextRequest = {
        nextUrl: "http://localhost:3000",
        headers: {
          get: jest.fn((key: string) => {
            if (key === "user-agent") return "Mozilla/5.0 (Next.js)";
            return null;
          }),
        },
      };

      mockIPExtractor.extract.mockReturnValue("10.0.0.1");

      ContextDetector.setContext(nextRequest);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("Mozilla/5.0 (Next.js)");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(nextRequest);
    });

    it("should return undefined when no context is set", () => {
      const context = ContextDetector.getContext();
      expect(context).toBeUndefined();
    });

    it("should handle null request", () => {
      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
    });

    it("should handle undefined request", () => {
      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBeUndefined();
      expect(context?.userAgent).toBeUndefined();
      expect(context?.framework).toBe("unknown");
    });

    it("should isolate context in async operations", async () => {
      const request1 = {
        app: { _router: {} },
        headers: { "user-agent": "Request 1" },
      };

      const request2 = {
        app: { _router: {} },
        headers: { "user-agent": "Request 2" },
      };

      mockIPExtractor.extract.mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request1);
      const context1 = ContextDetector.getContext();

      ContextDetector.setContext(request2);
      const context2 = ContextDetector.getContext();

      expect(context1?.userAgent).toBe("Request 1");
      expect(context2?.userAgent).toBe("Request 2");
    });
  });

  describe("detectFramework", () => {
    it("should detect Express framework", () => {
      const expressRequest = {
        app: { _router: {} },
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(expressRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });

    it("should detect Next.js framework", () => {
      const nextRequest = {
        nextUrl: "http://localhost:3000",
        headers: {
          get: jest.fn(),
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(nextRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("nextjs");
    });

    it("should return unknown for unrecognized framework", () => {
      const unknownRequest = {
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(unknownRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });

    it("should prefer Express detection when both indicators exist", () => {
      const ambiguousRequest = {
        app: { _router: {} },
        nextUrl: "http://localhost:3000",
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(ambiguousRequest);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("express");
    });
  });

  describe("extractUserAgent", () => {
    it("should extract User-Agent from Express request with lowercase header", () => {
      const request = {
        headers: {
          "user-agent": "Mozilla/5.0 Lowercase",
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Lowercase");
    });

    it("should extract User-Agent from Express request with capitalized header", () => {
      const request = {
        headers: {
          "User-Agent": "Mozilla/5.0 Capitalized",
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0 Capitalized");
    });

    it("should prefer lowercase user-agent over User-Agent", () => {
      const request = {
        headers: {
          "user-agent": "Lowercase Value",
          "User-Agent": "Uppercase Value",
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Lowercase Value");
    });

    it("should extract User-Agent from Next.js request using headers.get()", () => {
      const request = {
        headers: {
          get: jest.fn((key: string) => {
            if (key === "user-agent") return "Next.js User Agent";
            return null;
          }),
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Next.js User Agent");
      expect(request.headers.get).toHaveBeenCalledWith("user-agent");
    });

    it("should handle array User-Agent header value", () => {
      const request = {
        headers: {
          "user-agent": ["Mozilla/5.0", "Chrome/90.0"],
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("Mozilla/5.0");
    });

    it("should return undefined when User-Agent is missing", () => {
      const request = {
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when headers object is missing", () => {
      const request = {};

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined when Next.js headers.get() returns null", () => {
      const request = {
        headers: {
          get: jest.fn(() => null),
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should handle non-string User-Agent header value", () => {
      const request = {
        headers: {
          "user-agent": 12345,
        },
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });
  });

  describe("clearContext", () => {
    it("should not throw when called", () => {
      const request = {
        app: { _router: {} },
        headers: { "user-agent": "Test" },
      };

      mockIPExtractor.extract.mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request);
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });

  describe("IPExtractor integration", () => {
    it("should call IPExtractor.extract with the request", () => {
      const request = {
        headers: {},
        ip: "192.168.1.1",
      };

      mockIPExtractor.extract.mockReturnValue("192.168.1.1");

      ContextDetector.setContext(request);

      expect(mockIPExtractor.extract).toHaveBeenCalledWith(request);
      expect(mockIPExtractor.extract).toHaveBeenCalledTimes(1);
    });

    it("should store IP address from IPExtractor", () => {
      const request = {
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue("10.20.30.40");

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBe("10.20.30.40");
    });

    it("should handle undefined IP address from IPExtractor", () => {
      const request = {
        headers: {},
      };

      mockIPExtractor.extract.mockReturnValue(undefined);

      ContextDetector.setContext(request);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBeUndefined();
    });
  });
});