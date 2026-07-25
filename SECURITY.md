# Security Policy

NKC handles cryptographic keys, private conversations, device trust, and privacy-sensitive
network routing. Please report suspected vulnerabilities privately and avoid exposing user data,
keys, friend codes, onion addresses, credentials, or working exploit details in public issues.

## Supported Versions

NKC is in active development. Security fixes are applied to the latest published `0.4.x` release
and the current `main` branch.

| Version | Supported |
| --- | --- |
| Latest `0.4.x` release | Yes |
| Current `main` branch | Development fixes |
| Earlier releases | No |

## Reporting a Vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory flow for the
[`NyuKoP/NKC`](https://github.com/NyuKoP/NKC) repository. Include:

- The affected NKC version, operating system, and installation format
- A concise description of the impact and required preconditions
- Reproduction steps or a minimal proof of concept
- Relevant logs with all private content and identifiers removed
- Any suggested mitigation, if known

Do not open a public issue containing exploit details. If private reporting is unavailable,
contact the repository maintainer through GitHub without including sensitive details and request
a private reporting channel.

The maintainer will acknowledge a complete report, assess severity and affected versions, and
coordinate remediation and disclosure. Please allow time for a signed release to be built and
verified before public disclosure.

## Security Boundaries

Reports are especially valuable when they involve:

- Signature verification, ratchets, replay protection, or encrypted storage
- Start keys, identity keys, device pairing, or trust decisions
- Electron main/preload isolation, IPC validation, sandboxing, or navigation
- Onion routing, proxy policy, rendezvous origin approval, or IP disclosure
- Native worker integrity, scheduler validation, or packaged application loading
- Release signing, notarization, update metadata, or Tor checksum pins

Operational guidance for producing trusted artifacts is documented in
[Release Security](RELEASE-SECURITY.md). Transport and cryptographic requirements are documented
in [Transport Security Invariants](docs/SECURITY-transport-invariants.md).
