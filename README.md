# LoginLlama API Client

This TypeScript module provides an interface to interact with the LoginLlama API, which offers login status checks for users based on various parameters.

## Sign up for free at [loginllama.app](https://loginllama.app).

## Installation

Install via NPM. Requires Node.js 24 or higher (native fetch + crypto).

```
npm i -s loginllama
```

## Usage

First, import the necessary classes and types:

```typescript
import { LoginLlama } from "loginllama";
```

### Initialization

To initialize the `LoginLlama` class, you can either provide an API token directly or set it in the environment variable `LOGINLLAMA_API_KEY`. Pass `baseUrl` if you need to point at a mock server.

```typescript
const loginllama = new LoginLlama({ apiKey: "YOUR_API_TOKEN" });
```

Or, if using the environment variable of `LOGINLLAMA_API_KEY`:

```typescript
const loginllama = new LoginLlama(); // Pulls from the environment variable LOGINLLAMA_API_KEY
```

### Checking Login Status

The primary function provided by this module is `checkLogin`, which checks the login status of a user based on various parameters. A backwards-compatible `check_login` alias is still exported.

#### Parameters:

- `request` (optional): An Express request object. If provided, the IP address and user agent will be extracted from this object.
- `ipAddress` / `ip_address` (optional): The IP address of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `userAgent` / `user_agent` (optional): The user agent string of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `identityKey` / `identity_key`: The unique identity key for the user. This is a required parameter.
- `emailAddress`, `geoCountry`, `geoCity`, `userTimeOfDay`: Optional context fields.

#### Return Value:

The function returns a promise that resolves to a `LoginCheckResponse` object. This object contains the result of the login check, including `status`, `message`, `codes`, `risk_score`, `environment`, and optional `meta`.

#### Examples:

Using IP address and user agent directly:

```typescript
const loginCheckResult = await loginLlama.checkLogin({
  ipAddress: "192.168.1.1",
  userAgent: "Mozilla/5.0",
  identityKey: "user123",
});
```

Using an Express request object:

```typescript
const loginCheckResult = await loginLlama.checkLogin({
  request: req,
  identityKey: "user123",
});

if (loginCheckResult.status === "error" || loginCheckResult.risk_score >= 7) {
  // Block or challenge the login
}
```

### Webhook signature verification

Use `verifyWebhookSignature` to check the `X-LoginLlama-Signature` header against the raw request body:

```typescript
import { verifyWebhookSignature } from "loginllama";

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const valid = verifyWebhookSignature(
      req.body,
      req.headers["x-loginllama-signature"] as string,
      process.env.WEBHOOK_SECRET!
    );

    if (!valid) return res.status(401).send("Invalid signature");

    const event = JSON.parse(req.body.toString());
    // handle event...
    res.sendStatus(200);
  }
);
```

## Error Handling

The `check_login` function will throw errors if any of the required parameters (`ip_address`, `user_agent`, or `identity_key`) are missing (if `request` is not provided).

## API Endpoint

The default API endpoint used by this module is `https://loginllama.app/api/v1`.

## Login Status Codes

The module provides an enumeration `LoginCheckStatus` that lists various possible status codes returned by the LoginLlama API, such as `VALID`, `IP_ADDRESS_SUSPICIOUS`, `KNOWN_BOT`, etc.

## Contributing

If you find any issues or have suggestions for improvements, please open an issue or submit a pull request. Your contributions are welcome!

## License

This module is licensed under the GNU GPL V3 License.
