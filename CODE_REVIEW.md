# Code review and resolution

Initial review and fixes: 2026-09-19. The nine confirmed findings have been fixed.
The regression suite is in `test/regression.test.js`; run it with `npm test`.

## Resolved findings

| Initial finding | Resolution |
| --- | --- |
| Missing `node-forge` blocked package loading | Removed the unused decoding pass; JWT extracts the final certificate public key with built-in `crypto.X509Certificate`. |
| Status subscription threw `ReferenceError` | Fixed the instance receiver; automatic authorization subscriptions and repeated calls are tested. |
| Failed handshakes dereferenced a nonexistent connection | Forward the supplied error and reconnect after a defined delay. |
| Text structure files never reached the file callback | Track and serialize file requests; route text files to `message_file`, preserving correlation across interleaved control replies. |
| HTTP response chunks were parsed individually | Shared response reader collects bytes until `end`, with status/error handling, a 15-second inactivity timeout, and a 4 MiB limit. |
| Abort failed to stop pending retries | Retain and clear timer handles, guard stale callbacks, cancel version requests and handshakes, and reject late connections. |
| Specific text/daytimer/weather events emitted undefined | Emit text or the full event object, matching the generic event payload. |
| UUID parsing modified buffers | Read little-endian fields without mutation or undeclared globals. |
| Malformed binary messages caused uncaught exceptions | Validate headers, payload lengths, text alignment, and entry counts; emit `message_invalid` and close rather than guessing subsequent frame boundaries. |

## Other reviewed concerns addressed

- Declared Node support is now `>=22.0.0`, validated at that exact minimum.
- Added an executable test suite and README usage, options, events, and lifecycle
  documentation.
- Auth disposal cancels token refresh and HTTP requests. Long token lifetimes are
  rescheduled within Node's maximum timeout; disposed callbacks cannot send.
- Command/file dispatch uses local indices and removes one-time callbacks before
  invoking them, so nested dispatch cannot consume the wrong handler.
- Keepalive latency uses the send timestamp. The watchdog handles a missing first
  response, and close/error paths release both intervals.
- Reentrant abort from close/reconnect listeners cannot recursively emit close or
  leave another retry scheduled.

## Validation and limits

The tests exercise real modules using synthetic protocol buffers, controlled
transport events, mocked clocks, built-in certificate fixtures, and one locally
streamed HTTP response. All 40 tests passed on Node 22.0.0 and 25.9.0; JavaScript
syntax checks and `git diff --check` passed. A tarball installed into a fresh
temporary directory loaded the package and constructed JWT authentication using
only its declared dependencies.
No real Miniserver was contacted, so firmware interoperability still requires
hardware integration testing. This review does not claim exhaustive protocol
support or a comprehensive security audit.

The initial review read the README and relevant sections of the local
communication (V17.0), user-management (V17.0), structure-file (V17.1), and
operating-mode schedule (V14.4) PDFs. Those ignored documents are not committed.
