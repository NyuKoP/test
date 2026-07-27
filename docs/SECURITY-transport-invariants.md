# Transport Security Invariants

## Non-negotiable invariants
- Never claim Tor active unless proxy is reachable and address present.
- Forwarding must never return ok:true on failure.
- socks5h must use remote DNS (ATYP=0x03).
- Failover is allowed only in auto mode.
- Legacy local-only send does not leak to network.
- Onion inboxes must be registered by the trusted renderer IPC boundary. Inbox reads require the local mailbox capability, and routed writes carry the recipient capability from the friend code.
- Unknown mailbox IDs and incorrect mailbox capabilities must fail without exposing whether queued messages exist. Tokenless legacy ingress remains isolated by smaller item, byte, and lifetime limits.
- Hard timeouts and in-flight caps must be enforced.
- File chunks are 1 MiB and onion controller, transport-frame, Go request, and Go queue payloads are capped at 2 MiB; changing one limit requires reviewing all of them.
- File transfer must remain incremental and bounded-memory. Never assemble a 500 MiB Base64 payload in one allocation.
- Retried or replayed chunks must be deduplicated by authenticated event identity before file assembly.
- Internal Onion HELLO, ACK, PING, and PONG control messages must carry an Ed25519 signature from the known friend identity mapped to the sender device ID; unsigned, tampered, mismatched, or unknown identities are dropped.
- Security-sensitive identifiers and route secrets require cryptographically secure randomness. If `crypto.randomUUID` and `crypto.getRandomValues` are unavailable, creation must fail closed instead of using `Math.random`.
- Invalid signatures or friend-control protocol proofs are dropped and reported as dropped, never recorded as successfully handled.
- Diagnostic events must redact friend codes, onion addresses, IP addresses, device identifiers, credentials, keys, and message contents before console, browser-event, or file sinks.
- Windows installer scripts must pass filesystem paths as PowerShell arguments and use literal-path operations. Never interpolate downloaded or user-controlled paths into executable script text.

## Tests that enforce invariants
- `src/main/__tests__/socksHttpClient.test.ts`
- `src/main/__tests__/onionController.send.test.ts`
- `src/main/__tests__/onionController.security.test.ts`
- `src/main/__tests__/torMediaEnvelopeSize.test.ts`
- `src/main/__tests__/torLiveE2E.test.ts` (environment-gated)
- `src/main/onion/install/__tests__/unpack.security.test.ts`
- `src/net/internalOnion/__tests__/controlPlaneAuth.test.ts`
- `src/net/internalOnion/__tests__/relayNetwork.test.ts`
- `src/diagnostics/__tests__/infoCollectionLogs.test.ts`
