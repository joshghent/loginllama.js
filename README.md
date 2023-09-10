# LoginLlama API Client

This TypeScript module provides an interface to interact with the LoginLlama API, which offers login status checks for users based on various parameters.

## Sign up for free at [loginllama.app](https://loginllama.app).

## Installation

Install via NPM. Requires Node.js 18 or higher (as we use the Fetch API)

```
npm i -s loginllama
```

## Usage

First, import the necessary classes and types:

```typescript
import { LoginLlama } from "loginllama";
```

### Initialization

To initialize the `LoginLlama` class, you can either provide an API token directly or set it in the environment variable `LOGINLLAMA_API_KEY`.

```typescript
const loginllama = new LoginLlama("YOUR_API_TOKEN");
```

Or, if using the environment variable of `LOGINLLAMA_API_KEY`:

```typescript
const loginllama = new LoginLlama();
// Pulls from the environment variable LOGINLLAMA_API_KEY
```

### Checking Login Status

The primary function provided by this module is `check_login`, which checks the login status of a user based on various parameters.

#### Parameters:

- `request` (optional): An Express request object. If provided, the IP address and user agent will be extracted from this object.
- `ip_address` (optional): The IP address of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `user_agent` (optional): The user agent string of the user. If not provided and the `request` object is given, it will be extracted from the request.
- `identity_key`: The unique identity key for the user. This is a required parameter.

#### Return Value:

The function returns a promise that resolves to a `LoginCheck` object. This object contains the result of the login check, including the status, a message, and any applicable codes indicating the reason for the status.

#### Examples:

Using IP address and user agent directly:

```typescript
const loginCheckResult = await loginLlama.check_login({
  ip_address: "192.168.1.1",
  user_agent: "Mozilla/5.0",
  identity_key: "user123",
});
```

Using an Express request object:

```typescript
const loginCheckResult = await loginLlama.check_login({
  request: req,
  identity_key: "user123",
});
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
