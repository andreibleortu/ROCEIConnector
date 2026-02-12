//
// main.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "../Shared/ROCEISigningServiceProtocol.h"
#import "../Shared/PKCS11/PKCS11.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <bsm/libbsm.h>
#import <os/log.h>

// Private API: auditToken is more secure than processIdentifier because it includes
// both p_pid and p_idversion, preventing PID reuse race conditions.
// See: https://knight.sc/reverse%20engineering/2019/03/20/audit-tokens-explained.html
@interface NSXPCConnection (AuditToken)
@property (nonatomic, readonly) audit_token_t auditToken;
@end

/// XPC helper service that handles PKCS#11 operations outside the sandbox.
/// This service runs as a LaunchAgent and can access the PKCS#11 library
/// directly, which is necessary because the CryptoTokenKit extension runs in a
/// sandbox that may not have the required entitlements for PKCS#11 access.
@interface ROCEIHelperService
    : NSObject <NSXPCListenerDelegate, ROCEISigningServiceProtocol>
@property(nonatomic, strong)
    PKCS11Module *pkcs11Module; // Cached PKCS#11 module instance
@end

@implementation ROCEIHelperService

/// Accepts new XPC connections from clients (ROCEIConnector.app).
/// Validates the caller's code signature to prevent unauthorized access.
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: New XPC connection request");

  // SECURITY: Validate caller's code signature and team ID
  // This prevents any process from calling our helper service
  audit_token_t auditToken = newConnection.auditToken;

  // Get the PID from the audit token using BSM library function
  pid_t pid = audit_token_to_pid(auditToken);

  // Create a SecCode object from the audit token (more secure than PID alone)
  SecCodeRef codeRef = NULL;
  OSStatus status =
      SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef) @{
        (__bridge NSString *)kSecGuestAttributeAudit :
            [NSData dataWithBytes:&auditToken length:sizeof(auditToken)]
      },
                                     kSecCSDefaultFlags, &codeRef);

  if (status != errSecSuccess || !codeRef) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to get SecCode for PID %d: status=%d",
                 pid, status);
    return NO;
  }

  // SECURITY: Verify the code signature is cryptographically valid before
  // trusting the signing information.  Without this check, a process with a
  // tampered or ad-hoc signature could present matching identifiers.
  status = SecCodeCheckValidity(codeRef, kSecCSDefaultFlags, NULL);
  if (status != errSecSuccess) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Code signature validation FAILED for PID %d: "
                 "status=%d",
                 pid, status);
    CFRelease(codeRef);
    return NO;
  }

  // Get signing information
  CFDictionaryRef codeInfo = NULL;
  status = SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation,
                                         &codeInfo);
  CFRelease(codeRef);

  if (status != errSecSuccess || !codeInfo) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIHelper: Failed to get signing info for PID %d: status=%d", pid,
        status);
    return NO;
  }

  NSDictionary *info = (__bridge_transfer NSDictionary *)codeInfo;
  NSString *teamID = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
  NSString *bundleID = info[(__bridge NSString *)kSecCodeInfoIdentifier];

  os_log(
      OS_LOG_DEFAULT,
      "ROCEIHelper: Connection from PID %d, bundle=%{public}@, team=%{public}@",
      pid, bundleID ?: @"(none)", teamID ?: @"(none)");

  // SECURITY POLICY: Only accept connections from our main app or extension.
  // Use exact bundle ID allowlist (not prefix) to prevent any other app
  // signed with our team ID from connecting.
  NSSet<NSString *> *allowedBundleIDs = [NSSet setWithObjects:
      @"com.andrei.rocei.connector",           // Main app
      @"com.andrei.rocei.connector.extension", // CryptoTokenKit extension
      nil];

  BOOL validBundleID = [allowedBundleIDs containsObject:bundleID];

  // SECURITY: Dynamically extract the helper's own team ID via SecCodeCopySelf
  // so that developers building from source don't need to modify a hardcoded
  // constant.  The helper trusts callers signed with the same team identity.
  BOOL validTeamID = NO;
  SecCodeRef selfCode = NULL;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) == errSecSuccess) {
    CFDictionaryRef selfInfo = NULL;
    if (SecCodeCopySigningInformation(selfCode, kSecCSSigningInformation,
                                      &selfInfo) == errSecSuccess) {
      NSDictionary *selfDict = (__bridge_transfer NSDictionary *)selfInfo;
      NSString *selfTeamID =
          selfDict[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
      validTeamID = (selfTeamID != nil && teamID != nil &&
                     [teamID isEqualToString:selfTeamID]);
    } else {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: Failed to read own signing info");
    }
    if (selfCode) CFRelease(selfCode);
  } else {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: SecCodeCopySelf failed, falling back to "
                 "hardcoded team ID");
    validTeamID = [teamID isEqualToString:@"GUH3X26QND"];
  }

  if (!validBundleID || !validTeamID) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIHelper: REJECTED connection from bundle=%{public}@ team=%{public}@ - "
        "not in allowlist or wrong team ID",
        bundleID ?: @"(none)", teamID ?: @"(none)");
    return NO;
  }

  os_log(OS_LOG_DEFAULT,
         "ROCEIHelper: Connection validated successfully for %{public}@",
         bundleID);

  // Configure the connection to export our protocol interface
  newConnection.exportedInterface = [NSXPCInterface
      interfaceWithProtocol:@protocol(ROCEISigningServiceProtocol)];
  newConnection.exportedObject = self;

  // Configure the remote (client) interface for progress callbacks
  newConnection.remoteObjectInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(ROCEIProgressProtocol)];

  [newConnection resume];
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: Connection accepted and resumed");
  return YES;
}

/// Send a progress message back to the connector (non-blocking,
/// fire-and-forget). Uses NSXPCConnection.currentConnection to get the caller's
/// connection, ensuring proper routing even when multiple clients connect
/// simultaneously.
- (void)reportProgressToClient:(NSString *)step {
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: %{public}@", step);

  // Get the connection from the current XPC invocation context
  // This ensures progress goes to the right client even with concurrent
  // requests
  NSXPCConnection *conn = [NSXPCConnection currentConnection];
  if (conn) {
    id<ROCEIProgressProtocol> client =
        [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
          os_log_error(OS_LOG_DEFAULT,
                       "ROCEIHelper: Progress callback failed: %{public}@",
                       error);
        }];
    [client reportProgress:step];
  } else {
    os_log(OS_LOG_DEFAULT, "ROCEIHelper: No current connection for progress");
  }
}

/// Finds the PKCS#11 library path using the shared search order defined in
/// PKCS11.h. Returns nil and sets *error if the library is not found.
///
/// @param error Optional error output if library not found
/// @return Path to libidplug-pkcs11.dylib, or nil if not found
- (NSString *)findPKCS11LibraryPath:(NSError **)error {
  NSString *path = PKCS11FindLibraryPath();
  if (path) {
    os_log(OS_LOG_DEFAULT, "ROCEIHelper: Using PKCS#11: %{public}@", path);
    return path;
  }

  // Library not found
  if (error) {
    *error = [NSError errorWithDomain:@"ROCEIHelper"
                                 code:2
                             userInfo:@{
                               NSLocalizedDescriptionKey :
                                   @"libidplug-pkcs11.dylib not found. Install "
                                   @"IDplugManager.app first."
                             }];
  }
  return nil;
}

/// Enumerates certificates and keys from the PKCS#11 token for a given slot.
/// This is called by ROCEIConnector.app during token registration to fetch
/// certificate data that will be stored in the persistent token configuration.
///
/// Process:
/// 1. Initialize PKCS#11 module (cached to avoid re-initialization)
/// 2. Open session on specified slot (no PIN required for public data)
/// 3. Read certificate DER data
/// 4. Find corresponding public EC key and extract metadata
/// 5. Return certificate info via XPC reply block
///
/// @param slotNumber PKCS#11 slot ID (0x1 for authentication, 0x2 for signing)
/// @param reply Completion block with array of certificate info or error
- (void)enumerateCertificatesWithSlot:(NSNumber *)slotNumber
                                reply:
                                    (void (^)(NSArray<ROCEICertificateInfo *> *,
                                              NSError *))reply {
  os_log(OS_LOG_DEFAULT,
         "ROCEIHelper: enumerateCertificatesWithSlot called, slot=%@",
         slotNumber);

  NSError *error = nil;

  // Find the PKCS#11 library path
  NSString *modulePath = [self findPKCS11LibraryPath:&error];
  if (!modulePath) {
    [self reportProgressToClient:@"ERROR: PKCS#11 library not found"];
    reply(nil, error);
    return;
  }
  NSString *configDir = [modulePath stringByDeletingLastPathComponent];

  if (!self.pkcs11Module) {
    [self reportProgressToClient:@"Loading PKCS#11 library..."];
    self.pkcs11Module = [[PKCS11Module alloc] initWithModulePath:modulePath
                                                 configDirectory:configDir];
  }

  [self reportProgressToClient:@"Initializing PKCS#11 module..."];
  if (![self.pkcs11Module loadAndInitialize:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to load PKCS#11: %{public}@", error);
    [self
        reportProgressToClient:[NSString
                                   stringWithFormat:@"PKCS#11 init failed: %@",
                                                    error
                                                        .localizedDescription]];
    reply(nil, error);
    return;
  }

  // Mark module as in-use to prevent concurrent resetPKCS11 from
  // tearing down the library while we're mid-operation.
  [self.pkcs11Module beginUse];

  // Use slot ID directly (provided by caller) - avoid C_GetSlotList which can
  // crash with IDEMIA library
  CK_SLOT_ID slotID = (CK_SLOT_ID)[slotNumber unsignedLongValue];
  [self reportProgressToClient:
            [NSString stringWithFormat:@"Opening session on slot 0x%lx...",
                                       (unsigned long)slotID]];

  // Open PKCS#11 session (read-only, no PIN required for public key
  // enumeration)
  CK_SESSION_HANDLE session = 0;
  if (![self.pkcs11Module openSessionOnSlot:(uint32_t)slotID
                                    session:&session
                                      error:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to open session: %{public}@", error);
    [self
        reportProgressToClient:[NSString
                                   stringWithFormat:@"Session open failed: %@",
                                                    error
                                                        .localizedDescription]];
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }

  [self reportProgressToClient:@"Reading certificate from card..."];
  // Read certificate DER data (no PIN needed - certificates are public data)
  NSData *certData =
      [self.pkcs11Module readCertificateDERWithLabelSubstring:@"Authentication"
                                                      session:session
                                                        error:&error];

  if (!certData) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to read certificate: %{public}@", error);
    [self reportProgressToClient:
              [NSString stringWithFormat:@"Certificate read failed: %@",
                                         error.localizedDescription]];
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: Failed to close session: %{public}@",
                   closeError);
    }
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }

  // SECURITY: Basic DER validation - X.509 certificates must start with
  // SEQUENCE tag
  if (certData.length < 4 || ((const uint8_t *)certData.bytes)[0] != 0x30) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIHelper: Invalid certificate DER format (expected SEQUENCE tag)");
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: Failed to close session: %{public}@",
                   closeError);
    }
    NSError *invalidCertError = [NSError
        errorWithDomain:@"ROCEIHelper"
                   code:-1
               userInfo:@{
                 NSLocalizedDescriptionKey : @"Invalid certificate format"
               }];
    [self.pkcs11Module endUse];
    reply(nil, invalidCertError);
    return;
  }
  [self reportProgressToClient:
            [NSString stringWithFormat:@"Certificate read OK (%lu bytes)",
                                       (unsigned long)certData.length]];

  [self reportProgressToClient:@"Finding public EC key..."];
  // Find the corresponding public EC key to get key metadata
  NSData *keyID = nil;
  NSData *ecPoint = nil;
  NSNumber *keySizeBits = nil;
  if (![self.pkcs11Module findPublicECKeyWithLabelSubstring:@"Authentication"
                                                    session:session
                                                   keyIdOut:&keyID
                                                 ecPointOut:&ecPoint
                                             keySizeBitsOut:&keySizeBits
                                                      error:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to find public key: %{public}@", error);
    [self reportProgressToClient:
              [NSString stringWithFormat:@"Public key lookup failed: %@",
                                         error.localizedDescription]];
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: Failed to close session: %{public}@",
                   closeError);
    }
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }

  [self reportProgressToClient:[NSString
                                   stringWithFormat:@"Found EC key: %@ bits",
                                                    keySizeBits]];

  // Build certificate info object for XPC transfer
  ROCEICertificateInfo *info = [[ROCEICertificateInfo alloc] init];
  info.certificateDER = certData;
  info.keyID = keyID;
  info.label = @"RO CEI Authentication Certificate";
  info.keySizeBits = keySizeBits ? keySizeBits.unsignedIntegerValue : 256;
  info.publicKeyData = ecPoint;

  NSError *closeError = nil;
  if (![self.pkcs11Module closeSession:session error:&closeError]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: Failed to close session: %{public}@",
                 closeError);
  }
  [self.pkcs11Module endUse];
  [self reportProgressToClient:@"Sending certificate to connector..."];
  reply(@[ info ], nil);
}

/// Performs ECDSA signature operation using the PKCS#11 private key.
/// This is called by ROCEIPersistentSession via XPC to sign data outside the
/// sandbox. The helper has full access to PKCS#11 and can call C_Sign directly.
///
/// Process:
/// 1. Load/initialize PKCS#11 module (if not already loaded)
/// 2. Open session on specified slot
/// 3. Authenticate with PIN (C_Login)
/// 4. Find private key by CKA_ID
/// 5. Sign the pre-hashed digest using CKM_ECDSA mechanism
/// 6. Return raw signature bytes (r||s)
///
/// Security: PIN is cleared from memory after use. Sessions are logged out
/// and closed immediately after signing to minimize attack surface.
///
/// @param digest Pre-hashed digest to sign (20-64 bytes depending on hash algorithm)
/// @param keyID CKA_ID of the private key (from PKCS#11)
/// @param slot PKCS#11 slot ID (0x1 for authentication, 0x2 for signing)
/// @param pinData User's PIN as UTF-8 bytes
/// @param reply Completion block with signature data or error
- (void)signDigest:(NSData *)digest
         withKeyID:(NSData *)keyID
              slot:(NSNumber *)slot
           pinData:(NSData *)pinData
             reply:(void (^)(NSData *_Nullable, NSError *_Nullable))reply {
  os_log(OS_LOG_DEFAULT,
         "ROCEIHelper: signDigest called, digest length=%lu slot=0x%lx",
         (unsigned long)digest.length, slot.unsignedLongValue);

  NSError *error = nil;

  // Ensure PKCS#11 module is loaded
  if (!self.pkcs11Module) {
    // Find and load the PKCS#11 library
    NSString *modulePath = [self findPKCS11LibraryPath:&error];
    if (!modulePath) {
      reply(nil, error);
      return;
    }
    self.pkcs11Module = [[PKCS11Module alloc]
        initWithModulePath:modulePath
           configDirectory:[modulePath stringByDeletingLastPathComponent]];
  }

  // Initialize if needed
  if (![self.pkcs11Module loadAndInitialize:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: signDigest: Failed to init PKCS#11: %{public}@",
                 error);
    reply(nil, error);
    return;
  }

  // Mark module as in-use to prevent concurrent resetPKCS11 from
  // tearing down the library while we're mid-operation.
  [self.pkcs11Module beginUse];

  // Open session on the specified slot
  CK_SLOT_ID slotID = (CK_SLOT_ID)slot.unsignedLongValue;
  CK_SESSION_HANDLE session = 0;
  if (![self.pkcs11Module openSessionOnSlot:(uint32_t)slotID
                                    session:&session
                                      error:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: signDigest: Failed to open session: %{public}@",
                 error);
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: signDigest: Opened session 0x%lx",
         (unsigned long)session);

  // Login with PIN (required for private key operations)
  if (pinData.length > 0) {
    // Convert to mutable data for secure handling
    NSMutableData *mutablePinData = [pinData mutableCopy];

    if (![self.pkcs11Module loginUserOnSession:session
                                       pinData:mutablePinData
                                         error:&error]) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: signDigest: Login failed: %{public}@", error);
      NSError *closeError = nil;
      if (![self.pkcs11Module closeSession:session error:&closeError]) {
        os_log_error(OS_LOG_DEFAULT,
                     "ROCEIHelper: signDigest: Failed to close session after "
                     "login failure: %{public}@",
                     closeError);
      }

      // Enhance error message for user-facing presentation
      NSString *errorDesc = error.localizedDescription;
      if ([errorDesc containsString:@"permanently locked"]) {
        // Critical: card is bricked
        error = [NSError
            errorWithDomain:@"ROCEIHelper"
                       code:error.code
                   userInfo:@{
                     NSLocalizedDescriptionKey :
                         @"🔒 Your card is permanently locked. You must visit "
                         @"a government office to reset it.",
                     NSLocalizedRecoverySuggestionErrorKey :
                         @"The PIN was entered incorrectly too many times."
                   }];
      } else if ([errorDesc containsString:@"FINAL attempt"]) {
        // Warning: last chance
        error = [NSError
            errorWithDomain:@"ROCEIHelper"
                       code:error.code
                   userInfo:@{
                     NSLocalizedDescriptionKey :
                         @"⚠️ Incorrect PIN. You have ONE attempt remaining!",
                     NSLocalizedRecoverySuggestionErrorKey :
                         @"If you enter the wrong PIN again, your card will be "
                         @"permanently locked."
                   }];
      }

      [self.pkcs11Module endUse];
      reply(nil, error);
      return;
    }
    os_log(OS_LOG_DEFAULT, "ROCEIHelper: signDigest: Login successful");
    PKCS11SecureClearData(mutablePinData);
  } else {
    os_log_error(OS_LOG_DEFAULT, "ROCEIHelper: signDigest: No PIN provided");
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(
          OS_LOG_DEFAULT,
          "ROCEIHelper: signDigest: Failed to close session: %{public}@",
          closeError);
    }
    [self.pkcs11Module endUse];
    reply(nil, [NSError errorWithDomain:@"ROCEIHelper"
                                   code:3
                               userInfo:@{
                                 NSLocalizedDescriptionKey :
                                     @"PIN is required for signing"
                               }]);
    return;
  }

  // Find private key by CKA_ID
  CK_OBJECT_HANDLE privateKeyHandle = 0;
  if (![self.pkcs11Module findPrivateKeyById:keyID
                                     session:session
                                   objectOut:&privateKeyHandle
                                       error:&error]) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIHelper: signDigest: Failed to find private key: %{public}@",
        error);
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(
          OS_LOG_DEFAULT,
          "ROCEIHelper: signDigest: Failed to close session: %{public}@",
          closeError);
    }
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }
  os_log(OS_LOG_DEFAULT,
         "ROCEIHelper: signDigest: Found private key handle 0x%lx",
         (unsigned long)privateKeyHandle);

  // Sign the digest using CKM_ECDSA
  NSData *rawSignature = nil;
  if (![self.pkcs11Module ecdsaSignWithSession:session
                                    privateKey:privateKeyHandle
                                        digest:digest
                                  signatureOut:&rawSignature
                                         error:&error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: signDigest: Signing failed: %{public}@", error);
    NSError *closeError = nil;
    if (![self.pkcs11Module closeSession:session error:&closeError]) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIHelper: signDigest: Failed to close session after "
                   "signing failure: %{public}@",
                   closeError);
    }
    [self.pkcs11Module endUse];
    reply(nil, error);
    return;
  }

  // Logout and close session after successful signing
  NSError *logoutError = nil;
  if (![self.pkcs11Module logoutSession:session error:&logoutError]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: signDigest: Logout warning: %{public}@",
                 logoutError);
  }
  NSError *closeError = nil;
  if (![self.pkcs11Module closeSession:session error:&closeError]) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: signDigest: Failed to close session: %{public}@",
                 closeError);
  }
  [self.pkcs11Module endUse];
  os_log(OS_LOG_DEFAULT,
         "ROCEIHelper: signDigest: Signing succeeded, raw signature %lu bytes",
         (unsigned long)rawSignature.length);
  reply(rawSignature, nil);
}

/// Resets the PKCS#11 subsystem by calling C_Finalize to close all open
/// sessions and unloading the library. Used during troubleshooting to
/// recover from stuck or poisoned module states.
///
/// @param reply Completion block with success flag and descriptive message
- (void)resetPKCS11WithReply:(void (^)(BOOL, NSString *))reply {
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: resetPKCS11 called");

  if (!self.pkcs11Module) {
    os_log(OS_LOG_DEFAULT, "ROCEIHelper: resetPKCS11: no module loaded");
    reply(YES, @"No PKCS#11 module was loaded (nothing to reset)");
    return;
  }

  NSError *error = nil;
  BOOL ok = [self.pkcs11Module finalizeAndReset:&error];
  self.pkcs11Module = nil;

  if (ok) {
    os_log(
        OS_LOG_DEFAULT,
        "ROCEIHelper: resetPKCS11: C_Finalize succeeded, all sessions closed");
    reply(YES,
          @"C_Finalize succeeded — all sessions closed and library shut down");
  } else {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIHelper: resetPKCS11: C_Finalize failed: %{public}@",
                 error);
    reply(NO, [NSString stringWithFormat:@"C_Finalize failed: %@",
                                         error.localizedDescription]);
  }
}

/// Health-check endpoint. Returns YES with the service version string.
///
/// @param reply Completion block with success flag and version string
- (void)pingWithReply:(void (^)(BOOL, NSString *))reply {
  os_log(OS_LOG_DEFAULT, "ROCEIHelper: ping received");
  reply(YES, @"1.0");
}

@end

/// Main entry point for the XPC helper service.
/// This service runs as a LaunchAgent and listens for XPC connections from
/// ROCEIConnector.app. It handles PKCS#11 operations that require access
/// outside the CryptoTokenKit extension's sandbox.
int main(int argc, const char *argv[]) {
  @autoreleasepool {
    os_log(OS_LOG_DEFAULT, "ROCEIHelper: Starting XPC service");

    // Create service instance that implements ROCEISigningServiceProtocol
    ROCEIHelperService *service = [[ROCEIHelperService alloc] init];

    // Create XPC listener for Mach service
    // The Mach service name must match the one in the LaunchAgent plist
    NSXPCListener *listener = [[NSXPCListener alloc]
        initWithMachServiceName:@"com.andrei.rocei.connector.helper"];
    listener.delegate = service; // Service handles connection acceptance

    // Start listening for connections
    [listener resume];
    os_log(OS_LOG_DEFAULT,
           "ROCEIHelper: XPC listener started (service listener)");

    // Run the service's run loop to handle XPC messages
    // This blocks until the service is terminated
    [[NSRunLoop currentRunLoop] run];
  }
  return EXIT_SUCCESS;
}
