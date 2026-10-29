import Api from "../api";

const api = new Api({ "X-API-KEY": "key" }, "https://api.test/v1");
const realFetch = global.fetch;

afterEach(() => {
  global.fetch = realFetch;
});

// An outage must not block logins, so post() resolves with an "unavailable"
// result instead of rejecting.
describe("Api.post when LoginLlama cannot answer", () => {
  it("fails open on a network error", async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError("fetch failed"));

    await expect(api.post("/login/check")).resolves.toMatchObject({
      status: "unavailable",
      risk_score: 0,
      codes: [],
    });
  });

  it("fails open on a 5xx without a JSON body", async () => {
    global.fetch = jest
      .fn()
      .mockResolvedValue(new Response("Bad Gateway", { status: 502 }));

    await expect(api.post("/login/check")).resolves.toMatchObject({
      status: "unavailable",
      risk_score: 0,
    });
  });

  it("gives up after a timeout", async () => {
    global.fetch = jest.fn(
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal!.addEventListener("abort", () =>
            reject(init.signal!.reason)
          );
        })
    ) as unknown as typeof fetch;

    await expect(api.post("/login/check")).resolves.toMatchObject({
      status: "unavailable",
    });
  });
});

it("still returns the API's own error body", async () => {
  global.fetch = jest.fn().mockResolvedValue(
    new Response(
      JSON.stringify({ errors: [{ code: "quota_exceeded", title: "Quota" }] }),
      { status: 402 }
    )
  );

  await expect(api.post("/login/check")).resolves.toMatchObject({
    status: "error",
    error: "quota_exceeded",
  });
});
