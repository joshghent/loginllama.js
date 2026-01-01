import { JsonApiResponse, LoginCheckResponse, transformApiResponse } from "./types";

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

  public async post(url: string, params = {}): Promise<LoginCheckResponse> {
    const response = await fetch(`${this.baseUrl}${url}`, {
      method: "POST",
      body: JSON.stringify(params),
      headers: this.headers,
    });

    const json = (await response.json()) as JsonApiResponse;

    // Transform JSON:API format to the documented flat format
    const transformed = transformApiResponse(json);

    // If the HTTP response was not OK and we didn't get errors in the body,
    // throw an error with the status
    if (!response.ok && !json.errors) {
      throw new Error(`${response.status}: ${response.statusText}`);
    }

    return transformed;
  }
}
