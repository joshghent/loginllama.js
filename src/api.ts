import { JsonApiResponse, LoginCheckResponse, transformApiResponse } from "./types";

// Long enough for a normal check, short enough not to hold up a login.
const TIMEOUT_MS = 2000;

function unavailable(message: string): LoginCheckResponse {
  return {
    status: "unavailable",
    message,
    codes: [],
    risk_score: 0,
    environment: "unknown",
  };
}

export default class Api {
  headers: Headers;
  baseUrl: string;

  constructor(defaultHeaders: { [key: string]: string }, url: string) {
    this.headers = new Headers({
      "X-LOGINLLAMA-SOURCE": "node-sdk",
      "X-LOGINLLAMA-VERSION": "2",
      "Content-Type": "application/json",
      ...defaultHeaders,
    });
    this.baseUrl = url;
  }

  public async get(url: string): Promise<unknown> {
    const response = await fetch(`${this.baseUrl}${url}`, {
      method: "GET",
      headers: this.headers,
    });
    if (!response.ok) {
      throw new Error(`${response.status}: ${response.statusText}`);
    }
    return response.json();
  }

  // Fails open: when LoginLlama cannot answer, the result says so with a
  // risk score of 0 rather than rejecting, so an outage never blocks a login.
  public async post(url: string, params = {}): Promise<LoginCheckResponse> {
    let response: Response;
    let json: JsonApiResponse;
    try {
      response = await fetch(`${this.baseUrl}${url}`, {
        method: "POST",
        body: JSON.stringify(params),
        headers: this.headers,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      json = (await response.json()) as JsonApiResponse;
    } catch (error) {
      return unavailable(error instanceof Error ? error.message : String(error));
    }

    // An error body from the API is a real answer, such as a bad key or an
    // exhausted quota. Anything else that is not OK is an outage.
    if (!response.ok && !json.errors) {
      return unavailable(`${response.status}: ${response.statusText}`);
    }

    // Transform JSON:API format to the documented flat format
    return transformApiResponse(json);
  }
}
