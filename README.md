# LoginLlama API Client

Official Node.js/TypeScript SDK for [LoginLlama](https://loginllama.app) - AI-powered login security and fraud detection.

## Features

- **Automatic Context Detection**: Auto-detects IP address and User-Agent from Express, Next.js, and other frameworks
- **Multi-Source IP Extraction**: Supports X-Forwarded-For, CF-Connecting-IP, X-Real-IP, True-Client-IP with private IP filtering
- **Middleware Support**: Drop-in middleware for Express and Next.js
- **TypeScript**: Fully typed for excellent IDE support
- **Webhook Verification**: Built-in HMAC signature verification

## Installation

```bash
npm install loginllama@2.0.0
# or
pnpm add loginllama@2.0.0
```

Requires Node.js 22 or higher.

## Quick Start

### With Middleware (Recommended)

The simplest way to use LoginLlama is with the middleware pattern, which automatically captures request context:

```typescript
import { LoginLlama } from 'loginllama';
import express from 'express';

const app = express();
const loginllama = new LoginLlama({
  apiKey: process.env.LOGINLLAMA_API_KEY
});

// Add middleware to auto-capture request context
app.use(loginllama.middleware());

app.post('/login', async (req, res) => {
  try {
    // IP and User-Agent are automatically detected!
    const result = await loginllama.check(req.body.email);

    if (result.status === 'error' || result.risk_score > 5) {
      console.log('Suspicious login blocked:', result.codes);
      return res.status(403).json({ error: 'Login blocked' });
    }

    // Continue with login...
    res.json({ success: true });
  } catch (error) {
    console.error('LoginLlama error:', error);
    // Fail open on errors
    res.json({ success: true });
  }
});
```

### Without Middleware

If you prefer not to use middleware, you can pass the request explicitly:

```typescript
const result = await loginllama.check(req.body.email, {
  request: req
});
```

Or provide IP and User-Agent manually:

```typescript
const result = await loginllama.check('user@example.com', {
  ipAddress: '203.0.113.42',
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)...'
});
```

## Framework Examples

### Express

```typescript
import express from 'express';
import { LoginLlama } from 'loginllama';

const app = express();
const loginllama = new LoginLlama();

// Use middleware for automatic detection
app.use(loginllama.middleware());

app.post('/login', async (req, res) => {
  const result = await loginllama.check(req.body.email, {
    geoCountry: 'US',
    geoCity: 'San Francisco'
  });

  if (result.risk_score > 5) {
    return res.status(403).json({ error: 'Suspicious login' });
  }

  res.json({ success: true });
});
```

### Next.js App Router

```typescript
// app/api/login/route.ts
import { LoginLlama } from 'loginllama';
import { NextRequest, NextResponse } from 'next/server';

const loginllama = new LoginLlama();

export async function POST(request: NextRequest) {
  const body = await request.json();

  const result = await loginllama.check(body.email, {
    request: request // Pass Next.js request explicitly
  });

  if (result.risk_score > 5) {
    return NextResponse.json(
      { error: 'Login blocked' },
      { status: 403 }
    );
  }

  return NextResponse.json({ success: true });
}
```

### Next.js Pages Router

```typescript
// pages/api/login.ts
import { LoginLlama } from 'loginllama';
import type { NextApiRequest, NextApiResponse } from 'next';

const loginllama = new LoginLlama();

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const result = await loginllama.check(req.body.email, {
    request: req
  });

  if (result.risk_score > 5) {
    return res.status(403).json({ error: 'Login blocked' });
  }

  res.json({ success: true });
}
```

## API Reference

### `new LoginLlama(options)`

Create a new LoginLlama client.

**Options:**
- `apiKey` (optional): Your API key. Defaults to `LOGINLLAMA_API_KEY` environment variable
- `baseUrl` (optional): Custom API endpoint for testing

```typescript
const loginllama = new LoginLlama({
  apiKey: 'your-api-key'
});
```

### `loginllama.check(identityKey, options)`

Check a login attempt for suspicious activity.

**Parameters:**
- `identityKey` (required): User identifier (email, username, user ID, etc.)
- `options` (optional):
  - `ipAddress`: Override auto-detected IP address
  - `userAgent`: Override auto-detected User-Agent
  - `request`: Explicit request object (Express, Next.js)
  - `emailAddress`: User's email address for additional verification
  - `geoCountry`: ISO country code (e.g., 'US', 'GB')
  - `geoCity`: City name for additional context
  - `userTimeOfDay`: Time of login attempt

**Returns:** `Promise<LoginCheckResponse>`

```typescript
interface LoginCheckResponse {
  status: 'success' | 'error';
  message: string;
  codes: LoginCheckStatus[];
  risk_score: number; // 0-10 scale
  environment: string;
  meta?: Record<string, any>;
}
```

**Detection Priority:**
1. Explicit `ipAddress` and `userAgent` in options
2. Extract from `request` object if provided
3. Use async context from middleware (if used)

**Examples:**

```typescript
// Auto-detect from middleware context
const result = await loginllama.check('user@example.com');

// Pass request explicitly
const result = await loginllama.check('user@example.com', {
  request: req
});

// Manual override
const result = await loginllama.check('user@example.com', {
  ipAddress: '203.0.113.42',
  userAgent: 'Mozilla/5.0...'
});

// With additional context
const result = await loginllama.check('user@example.com', {
  emailAddress: 'user@example.com',
  geoCountry: 'US',
  geoCity: 'San Francisco'
});
```

### `loginllama.middleware()`

Returns Express/Next.js middleware that automatically captures request context using AsyncLocalStorage.

```typescript
app.use(loginllama.middleware());
```

### `verifyWebhookSignature(payload, signature, secret)`

Verify webhook signature using constant-time HMAC comparison.

**Parameters:**
- `payload`: Raw webhook body (string or Buffer)
- `signature`: Value from `X-LoginLlama-Signature` header
- `secret`: Webhook secret from LoginLlama dashboard

**Returns:** `boolean`

```typescript
import { verifyWebhookSignature } from 'loginllama';
import express from 'express';

app.post(
  '/webhook',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const valid = verifyWebhookSignature(
      req.body,
      req.headers['x-loginllama-signature'] as string,
      process.env.WEBHOOK_SECRET!
    );

    if (!valid) {
      return res.status(401).send('Invalid signature');
    }

    const event = JSON.parse(req.body.toString());
    // Handle event...
    res.sendStatus(200);
  }
);
```

## Login Status Codes

The SDK exports a `LoginCheckStatus` enum with all possible status codes:

```typescript
import { LoginCheckStatus } from 'loginllama';

// Example status codes:
LoginCheckStatus.VALID
LoginCheckStatus.IP_ADDRESS_SUSPICIOUS
LoginCheckStatus.KNOWN_BOT
LoginCheckStatus.GEO_IMPOSSIBLE_TRAVEL
LoginCheckStatus.USER_AGENT_SUSPICIOUS
// ... and more
```

## Error Handling

The SDK will throw errors if required parameters are missing:

```typescript
try {
  const result = await loginllama.check('user@example.com');
} catch (error) {
  if (error.message.includes('IP address could not be detected')) {
    // No IP available - pass { ipAddress } or { request } explicitly
    // or use middleware()
  }
  // Consider failing open on errors to avoid blocking legitimate users
}
```

**Best Practice:** Fail open on errors to avoid blocking legitimate users during API outages:

```typescript
try {
  const result = await loginllama.check(email);
  if (result.risk_score > 5) {
    // Block suspicious login
    return res.status(403).json({ error: 'Login blocked' });
  }
} catch (error) {
  console.error('LoginLlama error:', error);
  // Fail open - allow login to proceed
}
```

## IP Detection

The SDK automatically detects IP addresses from multiple sources with priority fallback:

1. **X-Forwarded-For** - Parses chain, takes first public IP (filters private IPs)
2. **CF-Connecting-IP** - Cloudflare real client IP
3. **X-Real-IP** - nginx proxy header
4. **True-Client-IP** - Akamai/Cloudflare header
5. **Direct connection** - `socket.remoteAddress`, `req.connection.remoteAddress`

**Private IP Filtering:** Automatically filters `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `127.x.x.x`, `::1`, `fc00::/7`, `fe80::/10`

## TypeScript Support

The SDK is written in TypeScript and includes full type definitions:

```typescript
import {
  LoginLlama,
  LoginCheckResponse,
  LoginCheckStatus,
  CheckOptions,
  verifyWebhookSignature
} from 'loginllama';
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/joshghent/loginllama-nodejs).

## License

GNU GPL V3 License

## Support

- Documentation: [loginllama.app/docs](https://loginllama.app/docs)
- Dashboard: [loginllama.app/dashboard](https://loginllama.app/dashboard)
- Issues: [GitHub Issues](https://github.com/joshghent/loginllama-nodejs/issues)
