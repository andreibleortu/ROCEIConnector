//
// TokenSession.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <CommonCrypto/CommonDigest.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Foundation/Foundation.h>
#import <os/log.h>
#import <string.h>

#import "../Shared/ROCEISigningServiceProtocol.h"
#import "../Shared/PKCS11/PKCS11.h"
#import "ROCEIExtensionShared.h"
#import "Token.h"
#import "TokenSession.h"

/// Securely clears sensitive data from memory using memset_s to prevent
/// compiler optimization. This is critical for PIN data to ensure it doesn't
/// remain in memory after use.
///
/// SECURITY LIMITATION: NSMutableData can be reallocated by the Objective-C
/// runtime (e.g., during appendData: or ARC temporary copies). This function
/// only clears the CURRENT buffer location; previous memory locations may
/// retain PIN residue until overwritten by other allocations or paged out.
///
/// This is unfixable in userland Objective-C without mlock'd C buffers. The
/// current approach matches typical macOS keychain agent implementations and
/// is considered acceptable for temporary PIN storage (cleared on dealloc).
///
/// @param data NSMutableData to clear
static void SecureClearData(NSMutableData *data) {
  if (data && data.length > 0) {
    memset_s(data.mutableBytes, data.length, 0, data.length);
  }
}

#pragma mark - Algorithm diagnostics and helpers for Safari TLS client authentication

/// Returns a human-readable string for a TKTokenKeyAlgorithm by probing known
/// ECDSA algorithms. Used for diagnostic logging when Safari or other apps
/// request signing operations.
static NSString *ROCEIAlgorithmName(TKTokenKeyAlgorithm *algorithm) {
  // Message variants (token must hash the data first)
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
    return @"ECDSASignatureMessageX962SHA384";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
    return @"ECDSASignatureMessageX962SHA256";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
    return @"ECDSASignatureMessageX962SHA1";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA224])
    return @"ECDSASignatureMessageX962SHA224";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA512])
    return @"ECDSASignatureMessageX962SHA512";
  // Digest variants (data is already hashed)
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384])
    return @"ECDSASignatureDigestX962SHA384";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256])
    return @"ECDSASignatureDigestX962SHA256";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1])
    return @"ECDSASignatureDigestX962SHA1";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA224])
    return @"ECDSASignatureDigestX962SHA224";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA512])
    return @"ECDSASignatureDigestX962SHA512";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962])
    return @"ECDSASignatureDigestX962 (raw)";
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureRFC4754])
    return @"ECDSASignatureRFC4754";
  return @"(unknown algorithm)";
}

/// Checks whether the given algorithm is a supported ECDSA algorithm for
/// signing. Supports both Message variants (Safari TLS) and Digest variants
/// (macOS login), including SHA-1 for TLS 1.2 compatibility.
///
/// @param algorithm The algorithm to check
/// @param keySizeBits The key size (256 or 384)
/// @return YES if the algorithm is supported for the given key size
static BOOL ROCEIIsECDSAAlgorithmSupported(TKTokenKeyAlgorithm *algorithm,
                                           NSInteger keySizeBits) {
  // Digest variants (pre-hashed data) -- used by macOS login and TLS stack
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256])
    return YES;
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384])
    return YES;
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1])
    return YES; // TLS 1.2
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962])
    return YES; // Raw digest

  // Message variants (raw data, token must hash) -- used by Safari TLS client
  // auth
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256])
    return YES;
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384])
    return YES;
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1])
    return YES; // TLS 1.2

  return NO;
}

/// Determines the digest to sign from the algorithm and input data.
/// For Message variants, hashes the input data using the appropriate algorithm.
/// For Digest variants, validates the input length and returns it as-is.
///
/// @param algorithm The TKTokenKeyAlgorithm
/// @param dataToSign The raw input data (message or pre-hashed digest)
/// @param keySizeBits Key size for fallback digest length selection
/// @param error Error output
/// @return The digest bytes to pass to PKCS#11, or nil on error
static NSData *_Nullable ROCEIDigestForSigning(TKTokenKeyAlgorithm *algorithm,
                                               NSData *dataToSign,
                                               NSInteger keySizeBits,
                                               NSError **error) {
  // --- Message variants: hash the data first ---
  // Guard against CC_LONG (uint32_t) overflow — data >4 GB is unrealistic for
  // TLS signing but we reject it explicitly rather than silently truncating.
  if (dataToSign.length > UINT32_MAX) {
    if (error)
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeBadParameter
                               userInfo:@{
                                 NSLocalizedDescriptionKey :
                                     @"Data too large for hashing (>4 GB)"
                               }];
    return nil;
  }

  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA384]) {
    uint8_t digest[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384(dataToSign.bytes, (CC_LONG)dataToSign.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA384_DIGEST_LENGTH];
  }
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA256]) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(dataToSign.bytes, (CC_LONG)dataToSign.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
  }
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureMessageX962SHA1]) {
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(dataToSign.bytes, (CC_LONG)dataToSign.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
  }

  // --- Digest variants: data is already hashed ---
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA384]) {
    if (dataToSign.length != CC_SHA384_DIGEST_LENGTH) {
      if (error)
        *error = [NSError errorWithDomain:TKErrorDomain
                                     code:TKErrorCodeBadParameter
                                 userInfo:@{
                                   NSLocalizedDescriptionKey :
                                       @"SHA-384 digest must be 48 bytes"
                                 }];
      return nil;
    }
    return dataToSign;
  }
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA256]) {
    if (dataToSign.length != CC_SHA256_DIGEST_LENGTH) {
      if (error)
        *error = [NSError errorWithDomain:TKErrorDomain
                                     code:TKErrorCodeBadParameter
                                 userInfo:@{
                                   NSLocalizedDescriptionKey :
                                       @"SHA-256 digest must be 32 bytes"
                                 }];
      return nil;
    }
    return dataToSign;
  }
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962SHA1]) {
    if (dataToSign.length != CC_SHA1_DIGEST_LENGTH) {
      if (error)
        *error = [NSError errorWithDomain:TKErrorDomain
                                     code:TKErrorCodeBadParameter
                                 userInfo:@{
                                   NSLocalizedDescriptionKey :
                                       @"SHA-1 digest must be 20 bytes"
                                 }];
      return nil;
    }
    return dataToSign;
  }
  // Raw digest (kSecKeyAlgorithmECDSASignatureDigestX962) -- accept any
  // reasonable length.  Minimum is curve order size: ceil(keySizeBits/8) bytes.
  // A shorter digest weakens the ECDSA signature.  Fall back to 20 (SHA-1) if
  // keySizeBits is unavailable.
  if ([algorithm isAlgorithm:kSecKeyAlgorithmECDSASignatureDigestX962]) {
    NSUInteger minLen = (keySizeBits > 0) ? (NSUInteger)((keySizeBits + 7) / 8) : 20;
    if (dataToSign.length < minLen || dataToSign.length > 64) {
      if (error)
        *error = [NSError errorWithDomain:TKErrorDomain
                                     code:TKErrorCodeBadParameter
                                 userInfo:@{
                                   NSLocalizedDescriptionKey :
                                       [NSString stringWithFormat:
                                           @"Raw digest length %lu out of "
                                           @"range [%lu..64]",
                                           (unsigned long)dataToSign.length,
                                           (unsigned long)minLen]
                                 }];
      return nil;
    }
    return dataToSign;
  }

  if (error)
    *error =
        [NSError errorWithDomain:TKErrorDomain
                            code:TKErrorCodeBadParameter
                        userInfo:@{
                          NSLocalizedDescriptionKey : @"Unsupported algorithm"
                        }];
  return nil;
}

/// Encodes a big-endian integer as a DER-encoded ASN.1 INTEGER.
/// This is used to convert ECDSA signature components (r, s) to DER format.
///
/// DER INTEGER encoding rules:
/// - Tag byte: 0x02
/// - Length byte(s): length of value
/// - Value: big-endian bytes, with leading zero padding if high bit is set (to
/// ensure positive)
///
/// @param rawBE Big-endian integer bytes (may have leading zeros)
/// @return DER-encoded INTEGER (tag + length + value)
static NSData *ROCEIASN1Integer(NSData *rawBE) {
  const uint8_t *p = rawBE.bytes;
  NSUInteger len = rawBE.length;

  // Skip leading zero bytes (but keep at least one byte for zero value)
  NSUInteger i = 0;
  while (i < len && p[i] == 0x00)
    i++;
  NSData *trimmed = (i == len)
                        ? [NSData dataWithBytes:"\x00" length:1]
                        : [rawBE subdataWithRange:NSMakeRange(i, len - i)];

  uint8_t first = ((const uint8_t *)trimmed.bytes)[0];
  NSMutableData *out = [NSMutableData data];
  uint8_t tag = 0x02; // INTEGER tag
  [out appendBytes:&tag length:1];

  // If high bit is set, add leading zero to ensure positive representation
  if (first & 0x80) {
    // DER short-form lengths are limited to 0–127 (0x00–0x7F).  For P-521
    // keys, each signature component can be up to 67 bytes (66 + leading
    // zero); this guard future-proofs against non-standard PKCS#11 modules.
    if (trimmed.length + 1 > 127) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIASN1Integer: length %lu + 1 exceeds DER "
                   "short-form limit (127)",
                   (unsigned long)trimmed.length);
      return nil;
    }
    uint8_t l = (uint8_t)(trimmed.length + 1);
    [out appendBytes:&l length:1];
    uint8_t zero = 0x00;
    [out appendBytes:&zero length:1];
    [out appendData:trimmed];
  } else {
    if (trimmed.length > 127) {
      os_log_error(OS_LOG_DEFAULT,
                   "ROCEIASN1Integer: length %lu exceeds DER short-form "
                   "limit (127)",
                   (unsigned long)trimmed.length);
      return nil;
    }
    uint8_t l = (uint8_t)trimmed.length;
    [out appendBytes:&l length:1];
    [out appendData:trimmed];
  }
  return out;
}

/// Converts a raw ECDSA signature from PKCS#11 format to DER X9.62 format.
///
/// PKCS#11 returns ECDSA signatures as concatenated r||s where:
/// - r and s are each keySize/8 bytes (e.g., 48 bytes each for secp384r1)
/// - Values are big-endian integers
///
/// macOS expects DER-encoded signatures per X9.62:
/// SEQUENCE {
///   INTEGER r,
///   INTEGER s
/// }
///
/// @param rawRS Concatenated r||s signature from PKCS#11 (must be even length)
/// @return DER-encoded signature, or nil if conversion fails
static NSData *_Nullable ROCEIECDSASignatureDERFromRaw(NSData *rawRS) {
  if (rawRS.length == 0 || (rawRS.length % 2) != 0)
    return nil;

  // Split into r and s components (each is half the total length)
  NSUInteger n = rawRS.length / 2;
  NSData *r = [rawRS subdataWithRange:NSMakeRange(0, n)];
  NSData *s = [rawRS subdataWithRange:NSMakeRange(n, n)];

  // Encode each as DER INTEGER
  NSData *ri = ROCEIASN1Integer(r);
  NSData *si = ROCEIASN1Integer(s);

  // Build SEQUENCE: 0x30 <length> <r> <s>
  NSUInteger seqLen = ri.length + si.length;
  NSMutableData *der = [NSMutableData dataWithCapacity:2 + seqLen];
  uint8_t seqTag = 0x30; // SEQUENCE tag
  [der appendBytes:&seqTag length:1];

  // Encode length (support both short-form and long-form)
  if (seqLen <= 0x7F) {
    // Short form: length fits in 7 bits
    uint8_t lenByte = (uint8_t)seqLen;
    [der appendBytes:&lenByte length:1];
  } else if (seqLen <= 0xFF) {
    // Long form: 1 byte for length value
    uint8_t lenHeader = 0x81; // High bit set + 1 byte follows
    uint8_t lenByte = (uint8_t)seqLen;
    [der appendBytes:&lenHeader length:1];
    [der appendBytes:&lenByte length:1];
  } else if (seqLen <= 0xFFFF) {
    // Long form: 2 bytes for length value
    uint8_t lenHeader = 0x82; // High bit set + 2 bytes follow
    uint8_t lenBytes[2] = {(uint8_t)(seqLen >> 8), (uint8_t)(seqLen & 0xFF)};
    [der appendBytes:&lenHeader length:1];
    [der appendBytes:lenBytes length:2];
  } else {
    // Shouldn't happen with ECDSA signatures (max P-521 is ~138 bytes)
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIECDSASignatureDERFromRaw: sequence length %lu exceeds maximum",
        (unsigned long)seqLen);
    return nil;
  }

  [der appendData:ri];
  [der appendData:si];
  return der;
}

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration
      // is active
@interface ROCEISession ()
@property(nonatomic, strong, nullable) NSMutableData *currentPIN;
@end
#endif

@interface ROCEIPersistentSession ()
/// Current PIN for authenticated session. Cleared with memset_s in dealloc.
///
/// SECURITY NOTE: NSMutableData may be reallocated by the runtime, leaving
/// residue in old memory locations. This is a fundamental limitation of
/// userland Objective-C memory management. The PIN is stored as briefly as
/// possible (only while the session is authenticated) and is cleared on
/// dealloc, which is the best-effort approach for macOS keychain-style apps.
@property(nonatomic, strong, nullable) NSMutableData *currentPIN;
@property(nonatomic, assign) BOOL authenticated;
@end

/// Extracts the JSON configuration dictionary from a persistent token's
/// configuration data. The configuration is set by ROCEIConnector.app during
/// token registration and contains:
/// - modulePath: Path to PKCS#11 library (e.g.,
/// "/Applications/IDplugManager.app/...")
/// - configDir: Directory for PKCS#11 config (usually same as modulePath's
/// parent)
/// - slot: PKCS#11 slot ID as hex string (e.g., "0x1" for authentication slot)
/// - certificateDER: Base64-encoded certificate (optional, for immediate token
/// publishing)
/// - keyID: Base64-encoded PKCS#11 CKA_ID (optional)
/// - keySizeBits: Key size in bits (256 or 384)
///
/// @param token The persistent token instance
/// @return Configuration dictionary, or empty dict if unavailable
static NSDictionary *PersistentCardConfig(TKToken *token) {
  if (@available(macOS 10.15, *)) {
    NSData *data = token.configuration.configurationData;
    if (data.length > 0) {
      id obj = [NSJSONSerialization JSONObjectWithData:data
                                               options:0
                                                 error:nil];
      if ([obj isKindOfClass:[NSDictionary class]]) {
        return obj;
      }
    }
  }
  return @{};
}

/// Parses the PKCS#11 slot ID from configuration.
/// Slot IDs for Romanian eID:
/// - 0x1: Authentication slot (4-digit PIN, used for macOS login)
/// - 0x2: Advanced Signature slot (6-digit PIN, used for document signing)
/// - 0x3: QSCD slot (6-digit PIN, usually empty on ID cards)
///
/// @param config Configuration dictionary from PersistentCardConfig
/// @return Slot number, or nil if not configured
static NSNumber *ConfiguredSlot(NSDictionary *config) {
  NSString *slotString = config[@"slot"];
  if (![slotString isKindOfClass:[NSString class]] || slotString.length == 0) {
    return nil;
  }
  // Parse hex string (supports "0x1", "0x2", etc.) with error checking
  const char *cstr = slotString.UTF8String;
  char *endptr = NULL;
  errno = 0;
  unsigned long value = strtoul(cstr, &endptr, 0);
  if (endptr == cstr || *endptr != '\0' || errno == ERANGE) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Invalid slot string '%{public}@', cannot parse",
                 slotString);
    return nil;
  }
  return @(value);
}

/// Returns a PKCS#11 module instance for the given token, using shared
/// singleton when possible. The shared singleton pattern avoids multiple
/// C_Initialize calls which can cause issues with the IDEMIA library. The
/// module path comes from token configuration.
///
/// @param token The token instance (persistent or smartcard)
/// @return PKCS#11 module instance, or nil on error
static PKCS11Module *ROCEIPKCS11ModuleForToken(TKToken *token) {
  NSDictionary *config = PersistentCardConfig(token);
  NSString *modulePath = [config[@"modulePath"] isKindOfClass:[NSString class]]
                             ? config[@"modulePath"]
                             : nil;
  NSString *configDir = [config[@"configDir"] isKindOfClass:[NSString class]]
                            ? config[@"configDir"]
                            : nil;
  if (modulePath.length > 0) {
    // Use shared singleton to avoid multiple C_Initialize calls
    return [PKCS11Module sharedModuleWithPath:modulePath
                              configDirectory:configDir];
  }
  // Fallback: use shared search order (should not happen for persistent tokens
  // with config)
  NSString *fallbackPath = PKCS11FindLibraryPath();
  if (fallbackPath) {
    return [PKCS11Module sharedModuleWithPath:fallbackPath
                              configDirectory:PKCS11ConfigDirectoryForPath(fallbackPath)];
  }
  return nil;
}

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration
      // is active
@implementation ROCEIAuthOperation

/// Initializes authentication operation for smartcard-based tokens.
/// Configures PIN format hints for the system PIN prompt dialog.
/// Note: The actual PIN policy (length, format) is enforced by the card, not by these hints.
- (instancetype)initWithSession:(ROCEISession *)session {
    if (self = [super init]) {
        _session = session;
        self.smartCard = session.smartCard;

        // Configure PIN prompt format hints (best-effort; actual card policy is unknown from PKCS#11).
        // Romanian eID cards use numeric PINs: 4 digits for authentication slot, 6 digits for signing slots.
        self.PINFormat = [[TKSmartCardPINFormat alloc] init];
        self.PINFormat.charset = TKSmartCardPINCharsetNumeric;
        self.PINFormat.encoding = TKSmartCardPINEncodingASCII;
        self.PINFormat.minPINLength = 4;  // Minimum (authentication slot)
        self.PINFormat.maxPINLength = 16;  // Maximum (covers all slots)
    }
    return self;
}

/// Verifies the PIN by attempting to log in to the PKCS#11 token.
/// On success, stores the PIN in the session for use in signing operations.
/// The PIN is verified immediately via C_Login to ensure it's correct before proceeding.
///
/// @param error Optional error output
/// @return YES if PIN verification succeeded, NO otherwise
- (BOOL)finishWithError:(NSError * _Nullable __autoreleasing *)error {
    if (self.PIN.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:nil];
        }
        return NO;
    }

    // Get PKCS#11 module and determine slot
    NSError *pkcs11Error = nil;
    PKCS11Module *module = ROCEIPKCS11ModuleForToken(self.session.token);
    NSDictionary *config = PersistentCardConfig(self.session.token);
    NSNumber *slot = ConfiguredSlot(config);
    if (slot == nil) {
        // Fallback: use first available slot (for smartcard tokens)
        slot = [module firstTokenSlot:&pkcs11Error];
    }
    CK_SESSION_HANDLE session = 0;

    // Mark module as in-use to prevent concurrent teardown
    [module beginUse];

    // Open session and verify PIN via C_Login
    // This immediately validates the PIN with the card before storing it
    if (slot == nil ||
        ![module openSessionOnSlot:(uint32_t)slot.unsignedIntValue session:&session error:&pkcs11Error] ||
        ![module loginUserOnSession:session pin:self.PIN error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: Session PIN verify failed via PKCS#11 (%{public}@)", pkcs11Error.localizedDescription);
        if (session != 0) {
            [module closeSession:session error:nil];  // Clean up session on error
        }
        [module endUse];
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:nil];
        }
        return NO;
    }

    // PIN verified successfully - close session and store PIN for signing operations
    [module closeSession:session error:nil];
    [module endUse];
    self.session.currentPIN = self.PIN;
    self.session.smartCard.context = @(YES);  // Mark smartcard context as authenticated
    self.session.authState = ROCEIAuthStateFreshlyAuthorized;
    return YES;
}

@end
#endif // DISABLED: smartcard mode

@interface ROCEIPasswordAuthOperation : TKTokenPasswordAuthOperation
@property(nonatomic, weak) ROCEIPersistentSession *session;
@end

@implementation ROCEIPasswordAuthOperation

- (instancetype)initWithSession:(ROCEIPersistentSession *)session {
  if (self = [super init]) {
    _session = session;
  }
  return self;
}

- (BOOL)finishWithError:(NSError *_Nullable __autoreleasing *)error {
  if (self.password.length == 0) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIPersistentCard auth operation: empty password");
    if (error) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeAuthenticationFailed
                               userInfo:nil];
    }
    return NO;
  }

  // For persistent tokens: Verify PIN immediately using bundled PKCS#11 library
  // This provides immediate feedback to the user if the PIN is incorrect

  // Get token configuration
  NSDictionary *config = PersistentCardConfig(self.session.token);
  NSNumber *slot = ConfiguredSlot(config);
  if (slot == nil) {
    slot = @(0x1); // Default to authentication slot
  }

  // Use shared library search order (appex Resources → App Support → IDplugManager)
  NSString *bundledLib = PKCS11FindLibraryPath();
  NSString *configDir = bundledLib ? PKCS11ConfigDirectoryForPath(bundledLib) : nil;

  // Declare variables before any goto to avoid ARC errors
  CK_SESSION_HANDLE verifySession = 0;
  NSError *verifyError = nil;
  // Create mutable copy so we can securely clear it after use
  NSMutableData *pinData =
      [[self.password dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];

  // Get or create PKCS11 module
  PKCS11Module *module = bundledLib
      ? [PKCS11Module sharedModuleWithPath:bundledLib
                            configDirectory:configDir]
      : nil;
  if (!module) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIPersistentCard auth: Failed to load bundled PKCS11 module");
    // SECURITY: Never store PIN without verification
    // Returning error ensures user knows authentication failed
    SecureClearData(pinData);
    if (error) {
      *error = [NSError
          errorWithDomain:TKErrorDomain
                     code:TKErrorCodeTokenNotFound
                 userInfo:@{
                   NSLocalizedDescriptionKey :
                       @"Failed to load PKCS#11 module for PIN verification"
                 }];
    }
    return NO;
  }

  // Mark module as in-use to prevent concurrent cache clears from
  // tearing it down while we're verifying the PIN.
  [module beginUse];

  // Try to verify PIN by opening a session and logging in

  BOOL pinValid = NO;
  if ([module openSessionOnSlot:(uint32_t)slot.unsignedIntValue
                        session:&verifySession
                          error:&verifyError]) {
    if ([module loginUserOnSession:verifySession
                           pinData:pinData
                             error:&verifyError]) {
      pinValid = YES;
      os_log(OS_LOG_DEFAULT,
             "ROCEIPersistentCard auth: PIN verified successfully");
      // Logout and close session after verification
      NSError *logoutError = nil;
      if (![module logoutSession:verifySession error:&logoutError]) {
        os_log_error(OS_LOG_DEFAULT,
                     "ROCEIPersistentCard auth: Logout warning: %{public}@",
                     logoutError);
      }
    } else {
      os_log_error(
          OS_LOG_DEFAULT,
          "ROCEIPersistentCard auth: PIN verification failed: %{public}@",
          verifyError);
    }
    NSError *closeError = nil;
    if (![module closeSession:verifySession error:&closeError]) {
      os_log_error(
          OS_LOG_DEFAULT,
          "ROCEIPersistentCard auth: Failed to close session: %{public}@",
          closeError);
    }
  } else {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIPersistentCard auth: Failed to open session for PIN "
                 "verification: %{public}@",
                 verifyError);
  }

  // If PIN verification failed, return error immediately
  if (!pinValid) {
    [module endUse];
    SecureClearData(pinData);
    if (error) {
      *error = [NSError
          errorWithDomain:TKErrorDomain
                     code:TKErrorCodeAuthenticationFailed
                 userInfo:@{NSLocalizedDescriptionKey : @"Incorrect PIN"}];
    }
    return NO;
  }

  // PIN verified successfully - store it for signing operations
  // Clear old PIN securely before storing new one
  if (self.session.currentPIN) {
    SecureClearData(self.session.currentPIN);
  }

  // Transfer ownership of pinData to currentPIN (already in secure mutable
  // format)
  self.session.currentPIN = pinData;
  self.session.authenticated = YES;
  [module endUse];
  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard auth operation: PIN stored successfully");
  return YES;
}

@end

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration
      // is active
@implementation ROCEISession

- (instancetype)initWithToken:(ROCEICard *)token {
    return [super initWithToken:token];
}

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session beginAuthForOperation:(TKTokenOperation)operation constraint:(TKTokenOperationConstraint)constraint error:(NSError * _Nullable __autoreleasing *)error {
    if (![constraint isEqual:ROCEIConstraintPIN] && ![constraint isEqual:ROCEIConstraintPINAlways]) {
        os_log_error(OS_LOG_DEFAULT, "attempt to evaluate unsupported constraint %@", constraint);
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        }
        return nil;
    }

    return [[ROCEIAuthOperation alloc] initWithSession:self];
}

- (BOOL)tokenSession:(TKTokenSession *)session supportsOperation:(TKTokenOperation)operation usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm {
    TKTokenKeychainKey *keyItem = (TKTokenKeychainKey *)[self.token.keychainContents keyForObjectID:keyObjectID error:nil];
    if (keyItem == nil) {
        return NO;
    }

    if (![keyItem.keyType isEqual:(id)kSecAttrKeyTypeECSECPrimeRandom]) {
        return NO;
    }

    if (operation == TKTokenOperationSignData && keyItem.canSign) {
        // Accept all supported ECDSA algorithms (Digest + Message variants, including SHA-1 for TLS 1.2)
        BOOL supported = ROCEIIsECDSAAlgorithmSupported(algorithm, keyItem.keySizeInBits);
        os_log(OS_LOG_DEFAULT, "ROCEICard supportsOperation SIGN: algorithm=%{public}@ keySize=%ld supported=%d",
               ROCEIAlgorithmName(algorithm), (long)keyItem.keySizeInBits, supported);
        return supported;
    }

    if (operation == TKTokenOperationPerformKeyExchange && keyItem.canPerformKeyExchange) {
        // Accept standard ECDH (no KDF — ctkbind applies its own KDF to the raw Z value)
        BOOL supported = ([algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeStandard] ||
                          [algorithm isAlgorithm:kSecKeyAlgorithmECDHKeyExchangeCofactor]);
        // Log algorithm description so we can identify what ctkbind probes
        os_log(OS_LOG_DEFAULT, "ROCEICard supportsOperation ECDH: alg=%{public}@ keySize=%ld supported=%d",
               (NSString *)CFBridgingRelease(CFCopyDescription((__bridge CFTypeRef)algorithm)),
               (long)keyItem.keySizeInBits, supported);
        return supported;
    }

    if (operation == TKTokenOperationDecryptData && keyItem.canDecrypt) {
        // Accept ALL EC decrypt algorithms — log the algorithm so we know exactly what ctkbind uses.
        // Returning YES here ensures ctkbind proceeds to decryptData: where we can see the algorithm.
        os_log(OS_LOG_DEFAULT, "ROCEICard supportsOperation DECRYPT(EC): alg=%{public}@ keySize=%ld supported=YES",
               (NSString *)CFBridgingRelease(CFCopyDescription((__bridge CFTypeRef)algorithm)),
               (long)keyItem.keySizeInBits);
        return YES;
    }

    return NO;
}

- (TKTokenKeychainKey *)authenticatedKeyForObjectID:(TKTokenObjectID)keyObjectID error:(NSError **)error {
    TKTokenKeychainKey *keyItem = (TKTokenKeychainKey *)[self.token.keychainContents keyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        return nil;
    }

    if (self.authState == ROCEIAuthStateUnauthorized || self.smartCard.context == nil || self.currentPIN.length == 0) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationNeeded userInfo:nil];
        }
        return nil;
    }
    return keyItem;
}

/// Signs data using the private key on the smartcard.
/// This is called by macOS Security framework when an application requests a signature
/// (e.g., during TLS client authentication in Safari or macOS login).
///
/// Supports both Message variants (raw data, hashed here) and Digest variants (pre-hashed).
///
/// Process:
/// 1. Determine digest from algorithm (hash if Message variant, validate if Digest variant)
/// 2. Open PKCS#11 session and authenticate with cached PIN
/// 3. Find private key by CKA_ID (stored in keyObjectID)
/// 4. Sign digest via CKM_ECDSA mechanism
/// 5. Convert raw r||s signature to DER format
/// 6. Cache certificate and key ID for next card insertion
///
/// @param session Token session
/// @param dataToSign Raw message or pre-hashed digest (depends on algorithm)
/// @param keyObjectID PKCS#11 CKA_ID bytes identifying the key pair
/// @param algorithm ECDSA signature algorithm (Message or Digest variant)
/// @param error Optional error output
/// @return DER-encoded ECDSA signature, or nil on error
- (NSData *)tokenSession:(TKTokenSession *)session signData:(NSData *)dataToSign usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError * _Nullable __autoreleasing *)error {
    // Verify authentication and get key item
    TKTokenKeychainKey *keyItem = [self authenticatedKeyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        return nil;
    }

    os_log(OS_LOG_DEFAULT, "ROCEICard signData: algorithm=%{public}@ inputLen=%lu",
           ROCEIAlgorithmName(algorithm), (unsigned long)dataToSign.length);

    // Compute digest: for Message variants, hash the input; for Digest variants, validate length
    NSData *digest = ROCEIDigestForSigning(algorithm, dataToSign, keyItem.keySizeInBits, error);
    if (digest == nil) {
        os_log_error(OS_LOG_DEFAULT, "ROCEICard signData: failed to compute digest for algorithm=%{public}@",
                     ROCEIAlgorithmName(algorithm));
        return nil;
    }

    if (![keyObjectID isKindOfClass:[NSData class]]) {
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        }
        return nil;
    }
    NSData *ckaId = (NSData *)keyObjectID;

    // Initialize PKCS#11 module and open session
    NSError *pkcs11Error = nil;
    NSString *libPath = PKCS11FindLibraryPath();
    PKCS11Module *module = libPath
        ? [PKCS11Module sharedModuleWithPath:libPath
                              configDirectory:PKCS11ConfigDirectoryForPath(libPath)]
        : nil;
    NSNumber *slot = [module firstTokenSlot:&pkcs11Error];
    CK_SESSION_HANDLE pkcsSession = 0;

    // Mark module as in-use to prevent concurrent teardown
    [module beginUse];

    // Open session and authenticate with cached PIN
    // Note: For smartcard tokens, we re-authenticate each time since sessions don't persist
    if (slot == nil ||
        ![module openSessionOnSlot:(uint32_t)slot.unsignedIntValue session:&pkcsSession error:&pkcs11Error] ||
        ![module loginUserOnSession:pkcsSession pinData:self.currentPIN error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: Session PKCS#11 login failed in sign (%{public}@)", pkcs11Error.localizedDescription);
        if (pkcsSession != 0) {
            [module closeSession:pkcsSession error:nil];  // Clean up session on error
        }
        [module endUse];
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:nil];
        }
        return nil;
    }

    // Find private key object by CKA_ID
    CK_OBJECT_HANDLE privKey = 0;
    if (![module findPrivateKeyById:ckaId session:pkcsSession objectOut:&privKey error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: Session private key not found (%{public}@)", pkcs11Error.localizedDescription);
        [module logoutSession:pkcsSession error:nil];
        [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        }
        return nil;
    }

    // Sign the digest using CKM_ECDSA mechanism
    // PKCS#11 CKM_ECDSA expects the digest as input (not the raw message)
    NSData *rawSig = nil;
    if (![module ecdsaSignWithSession:pkcsSession privateKey:privKey digest:digest signatureOut:&rawSig error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: Session sign failed (%{public}@)", pkcs11Error.localizedDescription);
        [module logoutSession:pkcsSession error:nil];
        [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCommunicationError userInfo:nil];
        }
        return nil;
    }

    // Convert raw r||s signature to DER X9.62 format for macOS compatibility
    NSData *derSig = ROCEIECDSASignatureDERFromRaw(rawSig);
    if (!derSig) {
        [module logoutSession:pkcsSession error:nil];
        [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:nil];
        }
        return nil;
    }

    // Cache CKA_ID for next card insertion
    // This allows Token.m to immediately publish the identity without requiring PIN entry first
    (void)ROCEIWriteCachedFile(@"auth_keyid.bin", ckaId, NULL);

    // Cache certificate if available (readable after authentication)
    // This enables immediate token publishing on next insertion
    NSData *certDER = [module readCertificateDERWithLabelSubstring:@"Certificate ECC Authentication" session:pkcsSession error:nil];
    if (certDER.length > 0) {
        (void)ROCEIWriteCachedFile(@"auth_cert.der", certDER, NULL);

        // Also cache SHA-256 hash of certificate for validation on next insertion
        // This prevents cached cert from being used if the card is swapped
        uint8_t certHash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(certDER.bytes, (CC_LONG)certDER.length, certHash);
        NSData *certHashData = [NSData dataWithBytes:certHash length:CC_SHA256_DIGEST_LENGTH];
        (void)ROCEIWriteCachedFile(@"auth_cert_hash.bin", certHashData, NULL);
        os_log(OS_LOG_DEFAULT, "Extension: Cached certificate hash for validation");
    }

    // Logout and close session after all operations complete (including certificate cache read)
    // Per PKCS#11 spec, C_Logout should be called before C_CloseSession to properly clear authentication state
    [module logoutSession:pkcsSession error:nil];
    [module closeSession:pkcsSession error:nil];
    [module endUse];

    self.authState = ROCEIAuthStateAuthorizedButAlreadyUsed;
    os_log(OS_LOG_DEFAULT, "ROCEICard signData: success, DER signature length=%lu", (unsigned long)derSig.length);
    return derSig;
}

/// Performs ECDH key exchange for macOS smart card pairing (called by ctkbind).
///
/// macOS pairing flow:
/// 1. ctkbind generates an ephemeral EC key pair
/// 2. Passes the ephemeral public key here as otherPartyPublicKeyData (04 || X || Y)
/// 3. We call C_DeriveKey(CKM_ECDH1_DERIVE + CKD_NULL) to get the raw Z value
/// 4. ctkbind uses the Z value to derive/wrap the per-user pairing credential
/// 5. The "Unpaired certificate" notification is replaced by pairing success
///
/// The certificate's key usage (Digital Signature) does NOT prevent ECDH — the card's
/// private key object must have CKA_DERIVE=TRUE, which is what slot 0x1 provides
/// (CKM_ECDH1_DERIVE is in the slot's mechanism list with HW+DERIVE flags).
- (NSData *)tokenSession:(TKTokenSession *)session
performKeyExchangeWithKey:(TKTokenObjectID)keyObjectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
 otherPartyPublicKeyData:(NSData *)otherPartyPublicKeyData
                      iv:(NSData *)iv
                   error:(NSError * _Nullable __autoreleasing *)error {
    TKTokenKeychainKey *keyItem = [self authenticatedKeyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        return nil;
    }

    os_log(OS_LOG_DEFAULT, "ROCEICard ECDH: otherPartyLen=%lu keySize=%ld",
           (unsigned long)otherPartyPublicKeyData.length, (long)keyItem.keySizeInBits);

    if (![keyObjectID isKindOfClass:[NSData class]]) {
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        return nil;
    }
    NSData *ckaId = (NSData *)keyObjectID;

    NSError *pkcs11Error = nil;
    NSString *libPath_ecdh = PKCS11FindLibraryPath();
    PKCS11Module *module = libPath_ecdh
        ? [PKCS11Module sharedModuleWithPath:libPath_ecdh
                              configDirectory:PKCS11ConfigDirectoryForPath(libPath_ecdh)]
        : nil;
    NSNumber *slot = [module firstTokenSlot:&pkcs11Error];
    CK_SESSION_HANDLE pkcsSession = 0;

    // Mark module as in-use to prevent concurrent teardown
    [module beginUse];

    if (slot == nil ||
        ![module openSessionOnSlot:(uint32_t)slot.unsignedIntValue session:&pkcsSession error:&pkcs11Error] ||
        ![module loginUserOnSession:pkcsSession pinData:self.currentPIN error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: ECDH login failed (%{public}@)", pkcs11Error.localizedDescription);
        if (pkcsSession != 0) [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:nil];
        return nil;
    }

    CK_OBJECT_HANDLE privKey = 0;
    if (![module findPrivateKeyById:ckaId session:pkcsSession objectOut:&privKey error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: ECDH private key not found (%{public}@)", pkcs11Error.localizedDescription);
        [module logoutSession:pkcsSession error:nil];
        [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        return nil;
    }

    // keySizeBytes = field size = number of bytes in X or Y coordinate (32 for P-256, 48 for P-384)
    NSUInteger keySizeBytes = (NSUInteger)((keyItem.keySizeInBits + 7) / 8);
    NSData *sharedSecret = [module ecdhDeriveWithSession:pkcsSession
                                              privateKey:privKey
                                       otherPublicKeyData:otherPartyPublicKeyData
                                            keySizeBytes:keySizeBytes
                                                   error:&pkcs11Error];

    // Logout and close session after ECDH operation
    [module logoutSession:pkcsSession error:nil];
    [module closeSession:pkcsSession error:nil];
    [module endUse];

    if (!sharedSecret) {
        os_log_error(OS_LOG_DEFAULT, "Extension: ECDH derive failed (%{public}@)", pkcs11Error.localizedDescription);
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCommunicationError userInfo:nil];
        return nil;
    }

    self.authState = ROCEIAuthStateAuthorizedButAlreadyUsed;
    os_log(OS_LOG_DEFAULT, "ROCEICard ECDH: success, sharedSecretLen=%lu", (unsigned long)sharedSecret.length);
    return sharedSecret;
}

/// Handles EC "decrypt" operations routed by ctkbind for smart card pairing.
///
/// ctkbind may detect the wrap key via `canDecrypt = YES` and call this method
/// instead of (or in addition to) performKeyExchangeWithKey:. For EC keys, macOS maps
/// "decrypt" to ECIES (ECDH + KDF + AES-GCM), but ctkbind's pairing protocol may only
/// need the ECDH shared secret. We handle the common cases:
///
/// - Ciphertext = uncompressed EC point (04 || X || Y):
///   Treat as raw ECDH with the provided ephemeral public key. Return Z (shared secret).
///
/// - Ciphertext = ECIES format (EC point || AES-GCM tag || ciphertext):
///   Extract ephemeral public key, perform ECDH, return Z. Full AES-GCM decryption
///   is NOT performed — ctkbind may only need Z for the pairing credential derivation.
- (NSData *)tokenSession:(TKTokenSession *)session decryptData:(NSData *)ciphertext usingKey:(TKTokenObjectID)keyObjectID algorithm:(TKTokenKeyAlgorithm *)algorithm error:(NSError * _Nullable __autoreleasing *)error {
    TKTokenKeychainKey *keyItem = [self authenticatedKeyForObjectID:keyObjectID error:error];
    if (keyItem == nil) {
        return nil;
    }

    os_log(OS_LOG_DEFAULT, "ROCEICard decryptData(EC): alg=%{public}@ ciphertextLen=%lu keySize=%ld",
           (NSString *)CFBridgingRelease(CFCopyDescription((__bridge CFTypeRef)algorithm)),
           (unsigned long)ciphertext.length, (long)keyItem.keySizeInBits);

    if (![keyObjectID isKindOfClass:[NSData class]]) {
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        return nil;
    }
    NSData *ckaId = (NSData *)keyObjectID;

    // Determine expected EC point length for the curve (P-256: 65 bytes, P-384: 97 bytes)
    NSUInteger keySizeBytes = (NSUInteger)((keyItem.keySizeInBits + 7) / 8);
    NSUInteger ecPointLen = 1 + 2 * keySizeBytes;  // 0x04 prefix + X + Y

    // Extract ephemeral public key from ciphertext:
    // - Raw ECDH: ciphertext IS the ephemeral public key (04 || X || Y)
    // - ECIES: ciphertext starts with ephemeral public key followed by AES-GCM data
    const uint8_t *bytes = ciphertext.bytes;
    NSData *ephemeralPubKey = nil;
    if (ciphertext.length >= ecPointLen && bytes[0] == 0x04) {
        ephemeralPubKey = [ciphertext subdataWithRange:NSMakeRange(0, ecPointLen)];
        os_log(OS_LOG_DEFAULT, "ROCEICard decryptData(EC): extracted ephemeral pubkey (%lu bytes)", (unsigned long)ecPointLen);
    } else {
        os_log_error(OS_LOG_DEFAULT, "ROCEICard decryptData(EC): ciphertext format unknown (len=%lu, first=0x%02x)",
                     (unsigned long)ciphertext.length, ciphertext.length > 0 ? bytes[0] : 0);
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeBadParameter userInfo:nil];
        return nil;
    }

    NSError *pkcs11Error = nil;
    NSString *libPath_d = PKCS11FindLibraryPath();
    PKCS11Module *module = libPath_d
        ? [PKCS11Module sharedModuleWithPath:libPath_d
                              configDirectory:PKCS11ConfigDirectoryForPath(libPath_d)]
        : nil;
    NSNumber *slot = [module firstTokenSlot:&pkcs11Error];
    CK_SESSION_HANDLE pkcsSession = 0;

    // Mark module as in-use to prevent concurrent teardown
    [module beginUse];

    if (slot == nil ||
        ![module openSessionOnSlot:(uint32_t)slot.unsignedIntValue session:&pkcsSession error:&pkcs11Error] ||
        ![module loginUserOnSession:pkcsSession pinData:self.currentPIN error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: decryptData(EC) login failed (%{public}@)", pkcs11Error.localizedDescription);
        if (pkcsSession != 0) [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeAuthenticationFailed userInfo:nil];
        return nil;
    }

    CK_OBJECT_HANDLE privKey = 0;
    if (![module findPrivateKeyById:ckaId session:pkcsSession objectOut:&privKey error:&pkcs11Error]) {
        os_log_error(OS_LOG_DEFAULT, "Extension: decryptData(EC) private key not found (%{public}@)", pkcs11Error.localizedDescription);
        [module logoutSession:pkcsSession error:nil];
        [module closeSession:pkcsSession error:nil];
        [module endUse];
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        return nil;
    }

    NSData *sharedSecret = [module ecdhDeriveWithSession:pkcsSession
                                              privateKey:privKey
                                       otherPublicKeyData:ephemeralPubKey
                                            keySizeBytes:keySizeBytes
                                                   error:&pkcs11Error];

    // Logout and close session after ECDH operation
    [module logoutSession:pkcsSession error:nil];
    [module closeSession:pkcsSession error:nil];
    [module endUse];

    if (!sharedSecret) {
        os_log_error(OS_LOG_DEFAULT, "Extension: decryptData(EC) ECDH derive failed (%{public}@)", pkcs11Error.localizedDescription);
        if (error) *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCommunicationError userInfo:nil];
        return nil;
    }

    self.authState = ROCEIAuthStateAuthorizedButAlreadyUsed;
    os_log(OS_LOG_DEFAULT, "ROCEICard decryptData(EC): ECDH success, sharedSecretLen=%lu", (unsigned long)sharedSecret.length);
    return sharedSecret;
}

@end
#endif // DISABLED: smartcard mode

@implementation ROCEIPersistentSession

- (instancetype)initWithToken:(TKToken *)token {
  if (self = [super initWithToken:token]) {
    _authenticated = NO;
  }
  return self;
}

- (void)dealloc {
  // Securely clear PIN from memory when session is deallocated.
  // NOTE: This clears the current NSMutableData buffer, but if the runtime
  // reallocated the buffer during the session lifetime, previous memory
  // locations may still contain PIN residue. This is a fundamental limitation
  // of managed memory in Objective-C and matches the security model of macOS
  // keychain agents.
  if (_currentPIN) {
    SecureClearData(_currentPIN);
    _currentPIN = nil;
  }
}

- (TKTokenAuthOperation *)tokenSession:(TKTokenSession *)session
                 beginAuthForOperation:(TKTokenOperation)operation
                            constraint:(TKTokenOperationConstraint)constraint
                                 error:(NSError *_Nullable __autoreleasing *)
                                           error {
  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard beginAuthForOperation: operation=%ld "
         "constraint=%{public}@",
         (long)operation, constraint);

  // Accept any constraint for persistent tokens - the system uses different
  // constraint formats
  if (constraint == nil || [constraint length] == 0) {
    os_log_error(
        OS_LOG_DEFAULT,
        "ROCEIPersistentCard beginAuthForOperation: nil or empty constraint");
    if (error) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeBadParameter
                               userInfo:nil];
    }
    return nil;
  }

  // For persistent tokens, accept any password-based constraint
  os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard beginAuthForOperation: creating "
                         "password auth operation");
  return [[ROCEIPasswordAuthOperation alloc] initWithSession:self];
}

- (BOOL)tokenSession:(TKTokenSession *)session
    supportsOperation:(TKTokenOperation)operation
             usingKey:(TKTokenObjectID)keyObjectID
            algorithm:(TKTokenKeyAlgorithm *)algorithm {
  // For persistent tokens, use configuration.keyForObjectID instead of
  // keychainContents
  TKTokenKeychainKey *keyItem = nil;
  if (@available(macOS 10.15, *)) {
    keyItem = (TKTokenKeychainKey *)[self.token.configuration
        keyForObjectID:keyObjectID
                 error:nil];
  }
  if (keyItem == nil) {
    os_log(OS_LOG_DEFAULT,
           "ROCEIPersistentCard supportsOperation: key not found for objectID");
    return NO;
  }
  if (operation != TKTokenOperationSignData || !keyItem.canSign) {
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard supportsOperation: unsupported "
                           "operation or key cannot sign");
    return NO;
  }
  if (![keyItem.keyType isEqual:(id)kSecAttrKeyTypeECSECPrimeRandom]) {
    os_log(OS_LOG_DEFAULT,
           "ROCEIPersistentCard supportsOperation: unsupported key type "
           "%{public}@",
           keyItem.keyType);
    return NO;
  }

  // Accept all supported ECDSA algorithms (Digest + Message variants, including
  // SHA-1 for TLS 1.2) Safari's TLS stack may request Message variants; macOS
  // login uses Digest variants.
  BOOL supported =
      ROCEIIsECDSAAlgorithmSupported(algorithm, keyItem.keySizeInBits);
  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard supportsOperation: algorithm=%{public}@ "
         "keySize=%ld supported=%d",
         ROCEIAlgorithmName(algorithm), (long)keyItem.keySizeInBits, supported);
  return supported;
}

- (TKTokenKeychainKey *)authenticatedKeyForObjectID:(TKTokenObjectID)keyObjectID
                                              error:(NSError **)error {
  // For persistent tokens, use configuration.keyForObjectID instead of
  // keychainContents
  TKTokenKeychainKey *keyItem = nil;
  if (@available(macOS 10.15, *)) {
    keyItem = (TKTokenKeychainKey *)[self.token.configuration
        keyForObjectID:keyObjectID
                 error:error];
  }
  if (keyItem == nil) {
    os_log(OS_LOG_DEFAULT,
           "ROCEIPersistentCard authenticatedKey: key not found for objectID");
    return nil;
  }
  if (!self.authenticated || self.currentPIN.length == 0) {
    os_log(OS_LOG_DEFAULT,
           "ROCEIPersistentCard authenticatedKey: not authenticated");
    if (error != nil) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeAuthenticationNeeded
                               userInfo:nil];
    }
    return nil;
  }
  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard authenticatedKey: found key, authenticated");
  return keyItem;
}

- (NSData *)tokenSession:(TKTokenSession *)session
                signData:(NSData *)dataToSign
                usingKey:(TKTokenObjectID)keyObjectID
               algorithm:(TKTokenKeyAlgorithm *)algorithm
                   error:(NSError *_Nullable __autoreleasing *)error {
  TKTokenKeychainKey *keyItem = [self authenticatedKeyForObjectID:keyObjectID
                                                            error:error];
  if (keyItem == nil) {
    return nil;
  }

  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard signData: algorithm=%{public}@ inputLen=%lu",
         ROCEIAlgorithmName(algorithm), (unsigned long)dataToSign.length);

  // Compute digest: for Message variants (Safari TLS), hash the input first;
  // for Digest variants (macOS login), validate length and pass through.
  NSData *digest = ROCEIDigestForSigning(algorithm, dataToSign,
                                         keyItem.keySizeInBits, error);
  if (digest == nil) {
    os_log_error(OS_LOG_DEFAULT,
                 "ROCEIPersistentCard signData: failed to compute digest for "
                 "algorithm=%{public}@",
                 ROCEIAlgorithmName(algorithm));
    return nil;
  }

  // Direct PKCS#11 signing using the library bundled in the extension's
  // Resources
  os_log(OS_LOG_DEFAULT,
         "Extension: signData begin via bundled PKCS11, digestLen=%lu keyID=%@",
         (unsigned long)digest.length, keyObjectID);

  // Get configuration
  NSDictionary *config = PersistentCardConfig(self.token);
  NSNumber *slot = ConfiguredSlot(config);
  if (slot == nil) {
    slot = @(0x1); // Default to authentication slot
  }

  // Use shared library search order (appex Resources → App Support → IDplugManager)
  NSString *bundledLib = PKCS11FindLibraryPath();
  NSString *configDir = bundledLib ? PKCS11ConfigDirectoryForPath(bundledLib) : nil;
  os_log(OS_LOG_DEFAULT,
         "Extension: Using bundled modulePath=%{public}@ slot=0x%lx",
         bundledLib, slot.unsignedLongValue);

  // Get or create PKCS11 module
  PKCS11Module *module = bundledLib
      ? [PKCS11Module sharedModuleWithPath:bundledLib
                            configDirectory:configDir]
      : nil;
  if (!module) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to load bundled PKCS11 module");
    if (error) {
      *error =
          [NSError errorWithDomain:TKErrorDomain
                              code:TKErrorCodeCommunicationError
                          userInfo:@{
                            NSLocalizedDescriptionKey :
                                @"Failed to initialize bundled PKCS#11 module"
                          }];
    }
    return nil;
  }

  // Mark module as in-use to prevent concurrent cache clears from
  // tearing it down while we're signing.
  [module beginUse];

  // Open session and login
  CK_SESSION_HANDLE pkcs11Session = 0;
  NSError *pkcs11Error = nil;
  if (![module openSessionOnSlot:(uint32_t)slot.unsignedIntValue
                         session:&pkcs11Session
                           error:&pkcs11Error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to open session: %{public}@", pkcs11Error);
    if (error)
      *error = pkcs11Error;
    [module endUse];
    return nil;
  }
  os_log(OS_LOG_DEFAULT, "Extension: Opened session 0x%lx",
         (unsigned long)pkcs11Session);

  // Login with PIN
  if (self.currentPIN.length > 0) {
    if (![module loginUserOnSession:pkcs11Session
                            pinData:self.currentPIN
                              error:&pkcs11Error]) {
      os_log_error(OS_LOG_DEFAULT, "Extension: Login failed: %{public}@",
                   pkcs11Error);
      // No logout needed since login failed
      [module closeSession:pkcs11Session
                     error:nil]; // Clean up session on error
      if (error)
        *error = pkcs11Error;
      [module endUse];
      return nil;
    }
    os_log(OS_LOG_DEFAULT, "Extension: Login successful");
  } else {
    os_log_error(OS_LOG_DEFAULT, "Extension: No PIN available, skipping login");
  }

  // Find private key by keyObjectID (which should be the CKA_ID)
  CK_OBJECT_HANDLE privateKey = 0;
  NSData *keyIdData = nil;
  if ([keyObjectID isKindOfClass:[NSData class]]) {
    keyIdData = (NSData *)keyObjectID;
  } else if ([keyObjectID isKindOfClass:[NSString class]]) {
    keyIdData =
        [(NSString *)keyObjectID dataUsingEncoding:NSUTF8StringEncoding];
  }

  if (keyIdData && ![module findPrivateKeyById:keyIdData
                                       session:pkcs11Session
                                     objectOut:&privateKey
                                         error:&pkcs11Error]) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to find private key: %{public}@",
                 pkcs11Error);
    // Logout before closing session
    [module logoutSession:pkcs11Session error:nil];
    [module closeSession:pkcs11Session error:nil]; // Clean up session on error
    if (error)
      *error = pkcs11Error;
    [module endUse];
    return nil;
  }
  os_log(OS_LOG_DEFAULT, "Extension: Found private key handle 0x%lx",
         (unsigned long)privateKey);

  // Sign the digest
  NSData *rawSignature = nil;
  if (![module ecdsaSignWithSession:pkcs11Session
                         privateKey:privateKey
                             digest:digest
                       signatureOut:&rawSignature
                              error:&pkcs11Error]) {
    os_log_error(OS_LOG_DEFAULT, "Extension: Signing failed: %{public}@",
                 pkcs11Error);
    // Logout before closing session
    [module logoutSession:pkcs11Session error:nil];
    [module closeSession:pkcs11Session error:nil]; // Clean up session on error
    if (error)
      *error = pkcs11Error;
    [module endUse];
    return nil;
  }

  os_log(OS_LOG_DEFAULT, "Extension: Raw PKCS#11 signature length=%lu",
         (unsigned long)rawSignature.length);

  // Convert raw r||s signature to DER X9.62 format
  NSData *derSignature = ROCEIECDSASignatureDERFromRaw(rawSignature);
  if (!derSignature) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to convert signature to DER");
    // Logout before closing session
    [module logoutSession:pkcs11Session error:nil];
    [module closeSession:pkcs11Session error:nil]; // Clean up session on error
    if (error) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeCorruptedData
                               userInfo:nil];
    }
    [module endUse];
    return nil;
  }

  // Logout and close session after successful signing
  [module logoutSession:pkcs11Session error:nil];
  [module closeSession:pkcs11Session error:nil];
  [module endUse];

  os_log(OS_LOG_DEFAULT,
         "ROCEIPersistentCard signData: success, DER signature length=%lu",
         (unsigned long)derSignature.length);
  return derSignature;
}

@end
