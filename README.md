# Loxone WSS Node API

WebSocket Secure Loxone API for Node.js, targeting second-generation Miniservers.
This is a continuation/fork of [node-lox-ws-api](https://github.com/alladdin/node-lox-ws-api)
that adds JWT tokens and additional control. Not affiliated with Loxone.

## Requirements and installation

Node.js **22.0.0 or later** is required. Earlier versions are not supported by the
current package, despite the older `>=4.2.6` declaration in previous revisions.

```sh
npm install loxone-wss-node-api
```

Use a hostname (optionally with a port) whose TLS certificate is trusted by Node.
Do not include a URL scheme or path in `host`.

## Connect and receive updates

```js
const API = require('loxone-wss-node-api');

const api = new API(
    process.env.LOXONE_HOST,
    process.env.LOXONE_USERNAME,
    process.env.LOXONE_PASSWORD,
    2,              // token permission bitmask; choose for your application
    'My Node app',  // description sent when acquiring a JWT
    true,           // reconnect automatically
    'JWT',
    30000,          // keepalive interval in milliseconds
    true,           // request LoxAPP3.json after authorization
    true            // subscribe to binary state updates
);

api.on('authorized', () => console.log('Authorized'));
api.on('connect_failed', error => console.error('Connection failed:', error.message));
api.on('connection_error', error => console.error('Transport error:', error.message));
api.on('auth_failed', () => console.error('Authorization failed'));
api.on('get_structure_file', structure => {
    // Match structure.controls and their state UUIDs with incoming updates.
    console.log('Structure received');
});
api.on('update_event_value', (uuid, value) => console.log(uuid, value));
api.on('update_event_text', (uuid, text) => console.log(uuid, text));

api.connect();
process.once('SIGINT', () => api.abort());
```

## Constructor options

Arguments are positional, in this order:

| Argument | Meaning / default |
| --- | --- |
| `host` | Miniserver hostname, optionally `hostname:port` |
| `username`, `password` | Account credentials |
| `permissions` | Token permission bitmask used for JWT acquisition |
| `info` | Application description used for JWT acquisition |
| `reconnect` | Disabled when omitted/false; `true` retries after 1 second; a positive finite number specifies milliseconds |
| `security` | `Hash` by default; also `AES-256-CBC`, `Token-Enc`, or `JWT` |
| `keepalive` | Interval in milliseconds; default 30000 |
| `request_structure_file` | Request structure after authorization; disabled by default |
| `request_status_updates` | Subscribe after authorization; disabled by default |

The version check selects JWT for firmware major version 10 or newer and
Token-Enc for version 9, overriding `security` in those cases. Transport uses
HTTPS/WSS; legacy AES and Token-Enc public-key requests still use HTTP.

## Commands and lifecycle

Wait for `authorized` before sending commands. `connect` means the WebSocket is
open, and `is_connected()` only indicates that a connection attempt/object exists.

- `send_control_command(uuidAction, command)` (alias `send_cmd`) sends a control
  command through the active authentication strategy.
- `send_command(command, secure = true, responseEntry)` sends a command. An
  optional response entry contains `{ control: RegExp, callback, onetime: boolean }`.
  The callback receives the parsed control response, including `control`, `code`,
  and `value`. The caller should check the response code.
- `enable_status_updates()` enables binary updates once per connection.
- `change_password(control, username, uuid, password, passwordScore)` requires JWT
  and returns a promise. `control` must be `updateuserpwdh` or `updateuservisupwdh`.
- `close()` ends the current connection and permits the configured automatic
  reconnect. `abort()` cancels retries, pending setup, and auth timers; an explicit
  later `connect()` starts again.

One-time callbacks are removed before invocation. Pending callbacks are discarded
on disconnect; they are not automatically replayed. In particular, a password
change promise has no built-in timeout and may remain pending on disconnect.

File downloads are serialized because file replies have no request ID. Control
commands can still run while a file is pending. Request `data/LoxAPP3.json` without
application encryption (`send_command('data/LoxAPP3.json', false)`); it is still
protected by WSS. Automatic structure retrieval registers its callback for you.
For other files, register a `file_chain` entry `{ file: RegExp, callback, onetime }`
before sending the unencrypted command, or listen for `message_file`.

## Events

- Lifecycle: `connect`, `authorized`, `auth_failed`, `connect_failed`,
  `connection_error`, `close`, `reconnect`, `abort`, `close_failed`, `already_connected`.
- `get_structure_file(structure)` supplies parsed `LoxAPP3.json`.
- `update_event_value(uuid, value)` and `update_event_text(uuid, text)` supply state
  values. `update_event_daytimer(uuid, event)` and `update_event_weather(uuid, event)`
  supply the complete decoded event, including `entry` arrays.
- Each update also has a UUID-specific event, for example
  `update_event_text_<uuid>(text)`, with the same payload and no UUID argument.
- Raw/decoded events include `handle_message`, `message_header`, `message_text`,
  `message_file`, and `message_event_table_values`, `message_event_table_text`,
  `message_event_table_daytimer`, `message_event_table_weather`.
- `message_invalid(message)` reports invalid protocol frames. The connection closes
  afterward and follows the configured reconnect policy.
- `keepalive(milliseconds)` reports round-trip latency (zero for an unsolicited
  reply). A missing reply for more than `keepalive + 2000` ms closes the connection.
- `info` provides diagnostics. `send` exposes outgoing command contents; avoid
  logging these indiscriminately because they may contain sensitive material.

HTTP setup requests have a 15-second inactivity timeout and a 4 MiB response limit.
Application event-listener exceptions propagate to the caller; they are not
reported as malformed protocol frames.

## Development

```sh
npm install
npm test
```

The suite uses Node's built-in test runner, synthetic protocol messages, mocked
transports/timers, and a loopback HTTP server. It does not require credentials or
operate a real Miniserver. Hardware interoperability remains to be tested.
See [AGENTS.md](AGENTS.md) for repository guidance and [CODE_REVIEW.md](CODE_REVIEW.md)
for the initial findings and their resolutions.
