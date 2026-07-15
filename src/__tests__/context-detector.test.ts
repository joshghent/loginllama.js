import { ContextDetector } from "../context-detector";
import { IPExtractor } from "../ip-extractor";

jest.mock("../ip-extractor", () => {
  return {
    IPExtractor: {
      extract: jest.fn(),
    },
  };
});

describe("ContextDetector", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("getContext", () => {
    it("should return undefined when no context has been set", () => {
      expect(ContextDetector.getContext()).toBeUndefined();
    });
  });

  describe("setContext / getContext", () => {
    it("should store and retrieve context for an Express-like request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("192.168.1.1");

      const req = {
        app: { _router: {} },
        headers: {
          "user-agent": "Mozilla/5.0",
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context).toBeDefined();
      expect(context?.ipAddress).toBe("192.168.1.1");
      expect(context?.userAgent).toBe("Mozilla/5.0");
      expect(context?.framework).toBe("express");
      expect(context?.rawRequest).toBe(req);
    });

    it("should store and retrieve context for a Next.js-like request", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("10.0.0.1");

      const req = {
        nextUrl: { pathname: "/api/test" },
        headers: {
          get: (key: string) =>
            key === "user-agent" ? "NextAgent/1.0" : null,
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.ipAddress).toBe("10.0.0.1");
      expect(context?.userAgent).toBe("NextAgent/1.0");
      expect(context?.framework).toBe("nextjs");
      expect(context?.rawRequest).toBe(req);
    });

    it("should detect unknown framework when neither express nor nextjs markers exist", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      const req = {
        headers: {},
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
    });

    it("should detect unknown framework when request is null", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(null);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
      expect(context?.userAgent).toBeUndefined();
    });

    it("should detect unknown framework when request is undefined", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue(undefined);

      ContextDetector.setContext(undefined);
      const context = ContextDetector.getContext();

      expect(context?.framework).toBe("unknown");
      expect(context?.userAgent).toBeUndefined();
    });

    it("should extract user-agent with capitalized header key", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("127.0.0.1");

      const req = {
        headers: {
          "User-Agent": "CapitalizedAgent/2.0",
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("CapitalizedAgent/2.0");
    });

    it("should extract user-agent from array header value", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("127.0.0.1");

      const req = {
        headers: {
          "user-agent": ["ArrayAgent/1.0", "SecondValue"],
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBe("ArrayAgent/1.0");
    });

    it("should return undefined user-agent when headers object has no user-agent", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("127.0.0.1");

      const req = {
        headers: {
          "content-type": "application/json",
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined user-agent when request has no headers", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("127.0.0.1");

      const req = {};

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should return undefined user-agent when headers.get returns null", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("127.0.0.1");

      const req = {
        nextUrl: {},
        headers: {
          get: () => null,
        },
      };

      ContextDetector.setContext(req);
      const context = ContextDetector.getContext();

      expect(context?.userAgent).toBeUndefined();
    });

    it("should call IPExtractor.extract with the request object", () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("8.8.8.8");

      const req = { headers: { "user-agent": "Test" } };
      ContextDetector.setContext(req);

      expect(IPExtractor.extract).toHaveBeenCalledWith(req);
    });

    it("should preserve context across async operations within the same async scope", async () => {
      (IPExtractor.extract as jest.Mock).mockReturnValue("1.2.3.4");

      const req = {
        app: { _router: {} },
        headers: { "user-agent": "AsyncAgent" },
      };

      ContextDetector.setContext(req);

      await new Promise((resolve) => setTimeout(resolve, 10));

      const context = ContextDetector.getContext();
      expect(context?.ipAddress).toBe("1.2.3.4");
      expect(context?.userAgent).toBe("AsyncAgent");
    });
  });

  describe("clearContext", () => {
    it("should not throw when called", () => {
      expect(() => ContextDetector.clearContext()).not.toThrow();
    });
  });
});