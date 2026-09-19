# Repository guidance

## Project and layout

This is a CommonJS Node.js library for communicating with Loxone Miniservers over
secure WebSockets. It is a fork of node-lox-ws-api, with JWT support, and is not
affiliated with Loxone. There is no build step or application executable.

- `lib/API.js`: package entry point; positional constructor options, authentication
  selection, reconnect lifecycle, response callbacks, subscriptions, and events.
- `lib/Connection.js`: `websocket` transport, keepalive timers, serialized file
  requests, and the binary header/payload state machine.
- `lib/Http.js`: bounded HTTP response assembly, errors, and request timeouts.
- `test/regression.test.js`: Node built-in test runner regression coverage.
- `lib/Auth/`: Hash, AES-256-CBC, Token-Enc, and JWT authentication strategies.
- `lib/Message/`: header, control response, file, UUID, and event-table decoders.
- `README.md`, `package.json`, and `LICENSE`: project overview and package metadata.
- `CODE_REVIEW.md`: findings from the initial review; verify against current code
  before treating an item as unresolved.

## Protocol references

The local `docs/` folder is ignored and may be absent in another checkout. When
available, consult the relevant PDF before changing wire formats:

- `1700_Communicating-with-the-Miniserver.pdf` (V17.0): connection setup, TLS,
  authentication, command encryption, header and event layouts, keepalive, and
  structure-file delivery. Particularly relevant: pages 7-10 and 17-30.
- `1700_Usermanagement.pdf` (V17.0): user-management commands; password updates
  and optional `hash|score` parameters are on page 9.
- `1701_Structure-File.pdf` (V17.1): `LoxAPP3.json`, control/state UUID mappings,
  and control-specific commands. Read the relevant control section as needed.
- `OperatingModeSchedule.pdf` (V14.4): calendar entry formats and commands.

These documents cover newer firmware than some legacy strategies. Preserve
version-specific behavior intentionally; do not assume every documented feature
is implemented. Keep ignored PDFs and extracted text out of commits.

## Working conventions

- Preserve CommonJS exports, constructor argument order, public method names,
  event names, and payload contracts unless a breaking change is requested.
- Match nearby formatting; most API/connection/JWT code uses four-space indents
  and prototype methods. Avoid unrelated style rewrites.
- Register response handlers before sending a command. Account for synchronous,
  nested dispatch when removing one-time callbacks.
- Keep HTTP response assembly separate from parsing: collect chunks and parse
  once on `end`; handle status, transport, and parsing failures.
- Preserve the header/payload state machine and distinguish text files from
  control responses. Validate lengths and counts before reading binary buffers.
- Preserve Loxone's UUID string format and little-endian fields. Decode without
  mutating input buffers; text events have four-byte alignment.
- Make reconnect, abort, and close manage all pending requests and timers;
  obsolete connections and auth objects must not revive themselves.
- Keep passwords, tokens, keys, and sensitive command contents out of new logs,
  fixtures, and committed artifacts. Use synthetic credentials in tests.
- Do not disable TLS verification as a routine connection fix.
- Preserve unrelated working-tree edits and ignored local resources.

## Setup and validation

`npm install` installs declared dependencies; `package-lock.json` and
`node_modules/` are currently ignored. On PowerShell, `npm.cmd` can be used when
the `npm.ps1` wrapper is restricted.

Run `npm test` for the regression suite (Node's built-in test runner). There is no
lint or CI configuration. JWT certificate extraction uses built-in crypto;
`node-forge` is not needed. The only declared runtime dependency is `websocket`.

For JavaScript changes:

1. Run `node --check <changed-file>` for syntax validation.
2. Exercise relevant behavior with synthetic buffers, mocked HTTP/WebSocket
   events, and controlled timers. Regression checks should cover observable
   outcomes, including failures and cleanup.
3. After dependency changes, verify that `require('./lib/API.js')` works with only
   declared dependencies in a clean installation.
4. Run real tests if introduced, and state any integration coverage gaps.

The supported Node engine is `>=22.0.0`. The regression suite was validated on
Node 22.0.0 and 25.9.0. Recheck the minimum version after introducing newer APIs.

An actual Miniserver is not required for unit-level checks. Hardware integration
requires an appropriate host, credentials, and authorization for the commands
being exercised; never issue real control or password-changing commands merely
to validate a parser or connection refactor.
