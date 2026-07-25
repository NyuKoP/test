# Contributing to NKC

Thank you for improving NKC. This project combines desktop UI, local encrypted storage, peer-to-peer networking, managed privacy runtimes, and a native worker. Keep changes focused and validate the layer you modify.

## Development Setup

1. Install Node.js, npm, and Go `1.26` or newer.
2. Install JavaScript dependencies with `npm install`.
3. Start the development application with `npm run dev`.

The renderer entry point is `src/main.tsx`, the Electron main process is `src/main.ts`, and the preload bridge is `src/preload.ts`.

## Before Submitting a Change

Run the checks relevant to your work:

```bash
npm run lint
npm run lint:encoding
npm test -- --run
npm run test:native
npm run build
npm audit --omit=dev --audit-level=high
```

Run `npm run test:ui` for user-flow or visual changes. Run the live Tor commands only when Tor is installed and the change affects its actual runtime path.

For file-transfer, controller body-limit, Go queue, or SOCKS transport changes, run at least:

```bash
npm run test:native
npx vitest run src/main/__tests__/torMediaEnvelopeSize.test.ts
npm run bench:transfer:500mb
```

Use the staged live commands (`test:tor:large`, `:10`, `:100`, and `:500`) in proportion to the risk. The 500 MiB Tor soak can take more than an hour and must not replace the faster local pipeline benchmark during normal iteration.

Focused tests are encouraged during development:

```bash
npx vitest run path/to/file.test.ts
npx eslint path/to/changed-file.ts
```

## Change Guidelines

- Preserve unrelated working-tree changes.
- Follow the existing architecture instead of creating parallel state, IPC, or transport layers.
- Keep Electron capabilities behind the preload bridge; do not expose unrestricted Node.js access to the renderer.
- Add or update tests for behavior changes and regressions.
- Avoid unrelated refactors in a focused bug fix.
- Keep logs free of message plaintext, keys, friend codes, credentials, IP addresses, ICE details, and other identifying routing metadata.
- Update documentation when commands, configuration, architecture, security guarantees, or user-visible workflows change.

## Security-Sensitive Changes

Changes in `src/crypto/`, `src/security/`, transport selection, persistence, device trust, or Electron IPC require extra care. Preserve the rules in [Transport Security Invariants](docs/SECURITY-transport-invariants.md), including signature verification before decryption and storage, encrypted-at-rest records, replay protection, and privacy-safe routing metadata.

Do not replace established cryptographic primitives or alter serialization/AAD formats without compatibility analysis and dedicated tests.

Payload-limit changes must remain consistent across `src/net/mediaTransferLimits.ts`, the Electron onion controller, renderer transport frame validation, and the Go transport/offline queue. Preserve bounded memory, inbox capacity limits, request timeouts, and retry caps when increasing throughput.

Changes to Electron packaging, signing, update publication, native-worker integrity, or Tor pin
maintenance must follow [Release Security](RELEASE-SECURITY.md). Do not publish an unsigned local
build as an official release. Tor pins must come through the dedicated workflow that verifies the
official checksum manifest and its pinned OpenPGP signing-key fingerprint.

## Native Worker

The native worker lives in `native/nkc-worker/` and is built into `native/bin/` by:

```bash
npm run build:native
```

Test it with:

```bash
npm run test:native
```

Set `GO_BINARY` only when the Go executable is not discoverable through the normal environment.

## Documentation

Documentation is written in English. Add durable technical documents under `docs/`, link them from [the documentation index](docs/README.md), and distinguish current behavior from historical phase notes.

## Commit Scope

Use small, descriptive commits. A commit should contain one coherent change and its tests or documentation. Do not commit generated build output, test reports, local logs, runtime data, or secrets.
