# RO CEI Connector

A CryptoTokenKit extension that enables macOS to use the Romanian electronic ID card (*Cartea Electronică de Identitate*) for authentication via the IDEMIA PKCS#11 library.

This implementation includes production-grade security hardening with defense-in-depth measures for concurrent access, XPC validation, and PKCS#11 interaction safety.

## What This Does

- Registers your Romanian eID certificate with macOS CryptoTokenKit
- Enables smart card authentication at the macOS login screen
- Makes the eID certificate available to `sc_auth` for pairing with your macOS user account
- **Enables TLS client certificate authentication in Safari** and other macOS apps that use the system TLS stack
- Provides ECDSA signing operations via the card's secure element

## Requirements

- **macOS 13.0** (Ventura) or later
- **Romanian electronic ID card** (*Cartea Electronică de Identitate*)
- **Smart card reader** (any PC/SC compatible reader)

## Installation

### Building from Source

**Prerequisites:**
- **IDPlug Manager** installed from [MAI Hub](https://hub.mai.gov.ro/aplicatie-cei) - provides the PKCS#11 library
    - Tested on and written for version 4.5.0.
    - The app verifies the SHA-512 hash of `/Applications/IDplugManager.app/Contents/Frameworks/libidplug-pkcs11.dylib` before loading it for security. Version 4.5.0's hash should be `ceae559a728f558e4813e28a6d7cb2fccfc604dbe8312c453f801fd878481e1edee3c048ec7b3cb7daaf169e8977c590a516fd792ae14397783bcaddaa39b928`.
    - Additional IDplugManager versions can be whitelisted by updating the hash array in `PKCS11.m` (see Technical Details below).
- [OpenSC](https://github.com/OpenSC/OpenSC) — provides `pkcs11-tool` used for smart card diagnostics. Download the macOS DMG from the [latest release](https://github.com/OpenSC/OpenSC/releases/latest) and follow the [macOS install guide](https://github.com/OpenSC/OpenSC/wiki/macOS-Quick-Start).
- Xcode 15.0 or later
- macOS 13.0+ (Ventura or later)
- An Apple Developer account (free tier works for development signing)

#### Option A: Command Line (recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/andreibleortu/ROCEIConnector.git
   cd ROCEIConnector
   ```

2. **Open in Xcode:**
   ```bash
   open ROCEIConnector.xcodeproj
   ```

2. **Configure code signing (first time only):**
   - The `ROCEIConnector` project should be open in Xcode
   - For each target (`ROCEIConnector`, `ROCEIExtension`, `ROCEIHelper`):
     - Go to "Signing & Capabilities"
     - Check "Automatically manage signing"
     - Select your Team/Apple ID

   > **Note:** Development signing is sufficient - no paid Apple Developer Program membership required.

3. **Build and install the application:**
   - **Build Release** (uses signing identity already configured in Xcode)
   ```bash
   xcodebuild -scheme ROCEIConnector -configuration Release -derivedDataPath build
   ```
   - **Install to /Applications**
   ```bash
   rm -rf "/Applications/RO CEI Connector.app"
   cp -R build/Build/Products/Release/"RO CEI Connector.app" /Applications/
   ```
   - **Launch** (registers extension and helper with macOS)
   ```bash
   open "/Applications/RO CEI Connector.app"
   ```

#### Option B: Xcode GUI

1. **Clone the repository:**
   ```bash
   git clone https://github.com/andreibleortu/ROCEIConnector.git
   cd ROCEIConnector
   ```

2. **Open in Xcode:**
   ```bash
   open ROCEIConnector.xcodeproj
   ```

3. **Configure code signing (first time only):**
   - The `ROCEIConnector` project should be open in Xcode
   - For each target (`ROCEIConnector`, `ROCEIExtension`, `ROCEIHelper`):
     - Go to "Signing & Capabilities"
     - Check "Automatically manage signing"
     - Select your Team/Apple ID

   > **Note:** Development signing is sufficient - no paid Apple Developer Program membership required.

4. **Build the application:**
   - Select scheme: **ROCEIConnector** (not ROCEIHelper or ROCEIExtension)
   - Switch to Release: Product → Scheme → Edit Scheme → Run → Build Configuration → **Release**
   - Product → Build (⌘B)

5. **Locate the built app:**

   ```bash
   find ~/Library/Developer/Xcode/DerivedData -name "RO CEI Connector.app" -path "*/Release/*" | head -1
   ```

6. **Install to Applications:**
   ```bash
   rm -rf "/Applications/RO CEI Connector.app"
   cp -R ~/Library/Developer/Xcode/DerivedData/ROCEIConnector-*/Build/Products/Release/"RO CEI Connector.app" /Applications/
   ```

   Or use Finder: drag `RO CEI Connector.app` to `/Applications`.

7. **First launch:**
   ```bash
   open "/Applications/RO CEI Connector.app"
   ```

   The app will:
   - Register the CTK extension with macOS
   - Install the XPC helper as a LaunchAgent
   - Display a status window

8. **Insert your Romanian eID card** and proceed to Usage section below.

> **Important:** The CryptoTokenKit extension may require a **reboot** to be fully activated by macOS. If the card is not detected after registration, restart your Mac.

## Usage

### GUI Application

The app features a clean vertical layout with commonly-used buttons and a collapsible Debug Tools panel:

**Main Actions (Left Panel):**

1. **Check Status**
   *Verify card & token status*
   Shows smart card identities, CTK tokens, PKCS#11 slots, and public keys

2. **Register Token**
   *Register certificate with macOS*
   Registers your eID certificate so it appears in `sc_auth identities`

3. **Test Sign**
   *Test signing with PIN*
   Tests ECDSA signing operation (prompts for PIN)

4. **Reset CTK Daemon**
   *Restart CryptoTokenKit to reload extension*
   Use this when extension was just installed but not detected

5. **Debug Tools ▶**
   *Expand/collapse debug panel*
   Click to expand a panel to the right with advanced troubleshooting tools

**Debug Tools Panel (Expandable to Right):**

When you click **Debug Tools**, the window extends to the right showing:

- **Verify Installation** - Check extension embedded and registered status
- **Clear Old Tokens** - Remove old ROCEITokenApp installations
- **Re-register Extension** - Force extension re-registration with pluginkit
- **Extension Info** - Show detailed bundle and registration information

The panel has a subtle background to separate it from the main interface.

**Quick Start:**
1. Launch **ROCEIConnector**
2. Insert your Romanian eID card
3. Click **Register Token**
4. Verify with: `sc_auth identities`
5. Pair for login: `sc_auth pair -u $USER -h <hash>`

**Troubleshooting:**
- If extension not detected: Click **Reset CTK Daemon**
- For installation verification: Click **Debug Tools ▶** then **Verify Installation**
- If old token causing issues: Click **Debug Tools ▶** then **Clear Old Tokens**

### Command Line

```bash
# Check token status
"/Applications/RO CEI Connector.app/Contents/MacOS/RO CEI Connector" --check-token

# Register token (authentication certificate, slot 0x1)
"/Applications/RO CEI Connector.app/Contents/MacOS/RO CEI Connector" --register-token

# Register signing certificate (slot 0x2, 6-digit PIN)
"/Applications/RO CEI Connector.app/Contents/MacOS/RO CEI Connector" --register-token --slot 0x2

# Test signing (prompts for PIN)
"/Applications/RO CEI Connector.app/Contents/MacOS/RO CEI Connector" --initialize
```

### Pairing with macOS Login

After registering the token:

```bash
# List available smart card identities
sc_auth identities

# Pair with your user account
sc_auth pair -u $USER -h <hash-from-identities>
```

### Safari / Website Authentication

After registering the token, the eID certificate is automatically available to Safari for TLS client certificate authentication (mTLS). This allows you to sign in to websites that accept certificate-based authentication.

**How it works:**

1. Register the token using the app (see above)
2. Navigate to a website that requests client certificate authentication
3. Safari will display a certificate picker showing your Romanian eID certificate ("RO CEI Authentication Certificate")
4. Select the certificate and click **Continue**
5. Enter your 4-digit PIN when prompted
6. The card signs the TLS handshake and you are authenticated

**Requirements:**

- The eID card **must be inserted** in the reader during authentication
- The website's server must be configured to request client certificates and trust the Romanian eID CA chain
- Works with Safari and any macOS application that uses the system TLS stack (e.g., `curl --cert`)
- Supports TLS 1.2 and TLS 1.3

**Supported algorithms:**

The extension handles all ECDSA signature algorithms used by Safari's TLS stack:
- Digest variants (pre-hashed): SHA-256, SHA-384, SHA-1
- Message variants (hash-then-sign): SHA-256, SHA-384, SHA-1

**Testing with `curl`:**

You can test client certificate authentication from the command line. After registering the token:

```bash
# List available identities (should show the eID certificate)
security find-identity -v -p ssl-client

# Use with curl (will prompt for PIN)
curl --cert "RO CEI Authentication Certificate" https://example-mtls-site.com/
```

> **Note:** The first time Safari accesses the token, macOS may show a keychain access dialog. Click **Allow** or **Always Allow** to permit Safari to use the certificate.

## Card Slots

The Romanian eID has three certificate slots:

| Slot | ID | Purpose | PIN Length |
|------|----|---------|------------|
| 0x1 | Authentication | macOS login, TLS client auth | 4 digits |
| 0x2 | Advanced Signature | Document signing (AdES) | 6 digits |
| 0x3 | QSCD | Qualified signatures - empty on IDs as of Jan 2026 | 6 digits |

This tool defaults to slot 0x1 (authentication). You can register other slots using `--slot 0x2` or `--slot 0x3`.

## Architecture

```
RO CEI Connector.app
├── Contents/MacOS/RO CEI Connector            # Main app executable
├── Contents/PlugIns/ROCEIExtension.appex      # CryptoTokenKit extension
├── Contents/Library/LoginItems/
│   └── RO CEI Connector Helper.app            # XPC helper (LaunchAgent)
└── Contents/Library/LaunchAgents/
    └── com.andrei.rocei.connector.helper.plist
```

**Components:**
- **ROCEIConnector** (main app): Registers the persistent token configuration with CryptoTokenKit and provides a diagnostic GUI
- **ROCEIExtension** (CTK extension): Handles `TKTokenSession` operations (PIN verification, ECDSA signing)
- **RO CEI Connector Helper** (XPC service): Background service that enumerates certificates from the PKCS#11 library. Validates connecting clients using audit tokens and code signature verification.

## Limitations

### No Keychain Auto-Unlock

The Romanian eID uses **EC (secp384r1) keys** which only support signing operations. macOS keychain auto-unlock requires key wrapping/unwrapping (an RSA-only operation), so:

- You **can** use the card for macOS login authentication
- You **cannot** use it to automatically unlock the keychain at login
- You'll need to enter your keychain password separately after login

This is a deliberate design choice by the Romanian government for security - the keys can never decrypt data, only sign it.

### Single Identity Pairing

macOS only allows pairing one smart card identity per user account. If you pair the authentication certificate (slot 0x1), the signing certificates (slots 0x2, 0x3) will still work for document signing applications but won't be paired for login.

## Troubleshooting

### Extension not embedded in app bundle

If `Contents/PlugIns/ROCEIExtension.appex` is missing from the built app:

```bash
# Verify the extension is missing
ls "/Applications/RO CEI Connector.app/Contents/PlugIns/"
# Should show: ROCEIExtension.appex
```

If missing, the Xcode project may have lost the embed configuration:
1. Open `ROCEIConnector.xcodeproj` in Xcode
2. Select the **ROCEIConnector** target (main app)
3. Go to **Build Phases** tab
4. Find **Embed Foundation Extensions** phase
5. If `ROCEIExtension.appex` is not listed, click **+** and add it
6. Clean and rebuild: Product → Clean Build Folder, then Product → Build

### Extension not registered with pluginkit

```bash
# Check if extension is registered
pluginkit -m -p com.apple.ctk-tokens | grep connector
```

If not listed:
```bash
# Kill the plugin daemon and relaunch the app
pluginkit -r "/Applications/RO CEI Connector.app"
killall -9 pluginkit
open "/Applications/RO CEI Connector.app"
```

### Token not appearing in `sc_auth identities`

```bash
# Restart CryptoTokenKit daemon
sudo killall -9 ctkd

# Re-register the token
"/Applications/RO CEI Connector.app/Contents/MacOS/RO CEI Connector" --register-token
```

### "Token driver configuration not found"

The CTK extension may not be discovered. Try:
1. Restart your Mac (extensions require reboot)
2. Check extension is registered: `pluginkit -m -p com.apple.ctk-tokens`

### PKCS#11 errors

Ensure IDPlug Manager is installed:
```bash
ls -la /Applications/IDplugManager.app/Contents/Frameworks/libidplug-pkcs11.dylib
```

Test with OpenSC tools:
```bash
pkcs11-tool --module /Applications/IDplugManager.app/Contents/Frameworks/libidplug-pkcs11.dylib --list-slots
```

### PIN blocked

After 3 incorrect PIN attempts, the card is blocked. You must visit a government office to unblock it.

## Technical Details

### Security Architecture

This application implements defense-in-depth security across multiple layers:

#### 1. XPC Service Isolation & Validation

The helper service (which accesses the PKCS#11 library) runs as a separate process with strict validation:

- **Audit token verification**: Validates connecting clients using `NSXPCConnection.auditToken` with `kSecGuestAttributeAudit`, which includes both PID and `p_idversion`. This prevents PID reuse race conditions where an attacker could hijack a recycled process ID.
- **Code signature enforcement**: Uses `SecCodeCopyGuestWithAttributes` + `SecCodeCopySigningInformation` to verify the caller is signed by the same team ID and has valid code signature.
- **Minimal privileges**: Helper runs with:
  - No App Sandbox (required to access PKCS#11 library)
  - Hardened Runtime enabled
  - No network access (incoming/outgoing disabled)
  - No camera, microphone, location, or other sensitive resources
  - BSM `libbsm` linked for proper audit token handling

#### 2. PKCS#11 Library Security

Loading and interacting with the native PKCS#11 library is protected at multiple levels:

- **SHA-512 hash verification**: Before `dlopen()`, the app computes and verifies the library hash against a whitelist of known-good versions for libraries loaded directly from IDplugManager. Bundled copies and Application Support cached copies skip hash verification because macOS may re-sign them (changing the hash); the bundled copy is covered by code signing, and the cached copy's source is validated before copying.
- **Multi-version support**: The hash whitelist (`knownGoodLibraryHashes()` in `PKCS11.m`) allows multiple IDplugManager versions, enabling version transitions without forced app updates.
- **Per-thread CWD changes**: Uses `__pthread_fchdir()` kernel syscall (macOS 10.5+) to change directory only for the calling thread during `dlopen()`. Falls back to serialized `fchdir()` if unavailable. This prevents other threads (including CryptoTokenKit internals) from observing changed working directory.
- **Timeout protection**: All blocking PKCS#11 calls (C_Login, C_Sign, etc.) run on background dispatch queues with timeouts to prevent indefinite hangs if the card becomes unresponsive.
- **Atomic reference counting**: Lock-free `atomic_int` tracks active PKCS#11 operations. `finalizeAndReset` waits (up to 10s) for operations to complete before teardown, preventing concurrent access during library unload.

#### 3. Cryptographic Data Handling

- **Keys never leave the card**: The eID uses EC keys in signing-only mode. Private keys cannot be extracted—all signing happens on the secure element.
- **PIN verification on-card**: PIN is passed directly to `C_Login` and verified by the card's firmware. The app never stores or logs PINs.
- **Defensive copies**: Sensitive data (PIN bytes, digests) are defensively copied before being passed to background dispatch blocks. This prevents use-after-free if the original data is cleared due to timeout.
- **Memory zeroing**: PIN data is explicitly zeroed after use (`resetBytesInRange:`) before deallocation.

#### 4. Input Validation & Data Integrity

- **DER encoding validation**: EC point data from PKCS#11 responses is validated for correct DER encoding:
  - Rejects non-minimal length encodings (e.g., `0x82 0x00 0x41` instead of `0x41`)
  - Validates that single-byte long-form lengths use the correct form
  - Prevents malformed data from reaching macOS TLS stack
- **Bounds checking**: All PKCS#11 attribute reads validate buffer sizes and ranges before access.
- **Signature format conversion**: Raw ECDSA signatures (r||s) are converted to DER X9.62 format with explicit length validation at each step.

#### 5. Sandboxing & Process Isolation

- **CryptoTokenKit extension**: Runs in Apple's CTK sandbox with restricted capabilities. Extension has no direct PKCS#11 access—all operations proxy through the helper XPC service.
- **Main app**: Limited entitlements—only what's needed for token registration and XPC.
- **Helper service**: Registered via Service Management framework, runs on-demand, automatically terminates when idle.

#### 6. Concurrency Safety

- **No shared mutable state**: PKCS#11 module instances use either:
  - Cached shared instances (protected by beginUse/endUse reference counting)
  - Or per-operation instances (allocated fresh, no sharing)
- **Thread-safe module cache**: `clearSharedModuleCache` skips modules with active operations (`activeUseCount > 0`).
- **Explicit operation bracketing**: All multi-step PKCS#11 operations (open session → login → sign → logout → close) are wrapped in `beginUse`/`endUse` pairs with proper cleanup on all exit paths (success and error).

#### 7. Error Handling & Fail-Safe Defaults

- **Conservative timeouts**: 30s for C_Login, 60s for C_Sign—generous to accommodate slow readers but prevents indefinite blocking.
- **Graceful degradation**: If `__pthread_fchdir()` unavailable, falls back to serialized `fchdir()` with dispatch semaphore.
- **Early validation**: Hash verification happens before `dlopen()`, so tampered libraries are rejected before any code execution.
- **Detailed error reporting**: User-facing errors include actionable information (e.g., "incompatible IDplugManager version" with expected hashes).

### Implementation Details

- Uses PKCS#11 API via direct `dlsym` calls (the IDEMIA library has non-standard function list offsets)
- Converts raw ECDSA signatures (r||s) to DER X9.62 format for macOS compatibility
- Implements `TKTokenDriver` with persistent token configuration (macOS 10.15+)
- XPC helper registered via `SMAppService` (Service Management framework)
- Supports both Message and Digest ECDSA algorithm variants for Safari TLS client authentication
- Handles SHA-1, SHA-256, and SHA-384 digest algorithms for TLS 1.2/1.3 compatibility

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).

See [LICENSE](LICENSE) for the full license text and [NOTICE.md](NOTICE.md) for third-party attributions.

### Third-Party Code

Portions of this software are based on Apple Inc.'s PIVToken sample code (Copyright 2016),
used under Apple's sample code license and redistributed under AGPL-3.0.

## Acknowledgments

- Based on Apple's CryptoTokenKit sample code
- Uses the IDEMIA PKCS#11 library provided by the Romanian Ministry for Internal Affairs
