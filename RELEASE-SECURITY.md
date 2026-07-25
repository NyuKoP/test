# Release security

NKC release artifacts must be produced by the tag-triggered GitHub Actions release workflow.
Do not publish artifacts from an unsigned local build.

## Required repository secrets

Windows:

- `WIN_CSC_LINK`: base64-encoded certificate, HTTPS certificate URL, or supported signing-certificate reference
- `WIN_CSC_KEY_PASSWORD`: certificate password

macOS:

- `MAC_CSC_LINK`: Developer ID Application certificate
- `MAC_CSC_KEY_PASSWORD`: certificate password
- `APPLE_ID`: notarization account
- `APPLE_APP_SPECIFIC_PASSWORD`: app-specific password
- `APPLE_TEAM_ID`: Apple Developer team ID

The workflows fail closed when these values are absent. macOS builds use hardened runtime,
notarization, and stapling through electron-builder. Windows builds sign the application,
embedded executable resources, and NSIS installer after Electron Fuses have been applied.

## Release verification

Before publishing:

1. Verify Windows signatures with `Get-AuthenticodeSignature` or `signtool verify /pa /all`.
2. Verify macOS with `codesign --verify --deep --strict` and
   `spctl --assess --type execute`.
3. Confirm the macOS notarization ticket with `xcrun stapler validate`.
4. Read Electron Fuses from the packaged executable and confirm that Run-as-Node,
   Node options, CLI inspection, and extra `file://` privileges are disabled.
5. Run `npm audit --omit=dev --audit-level=high`, the unit suite, and the packaged
   hardened-process smoke test.

Tor checksum pins are updated only through the dedicated pull-request workflow. That workflow
verifies the checksum manifest with the pinned Tor Browser Developers OpenPGP fingerprint before
changing source-controlled hashes. Release jobs never refresh pins from the network.
