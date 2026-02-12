//
// Token.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Foundation/Foundation.h>
#import <os/log.h>

#import "NSData_Zip.h"
#import "../Shared/PKCS11/PKCS11.h"
#import "ROCEIExtensionShared.h"
#import "Token.h"

@implementation NSData (hexString)

/// Converts binary data to a hexadecimal string representation.
/// Each byte is represented as two uppercase hexadecimal digits.
///
/// @return Hexadecimal string (e.g., "A1B2C3" for bytes {0xA1, 0xB2, 0xC3})
- (NSString *)hexString {

  NSUInteger capacity = self.length * 2;
  NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:capacity];
  const unsigned char *dataBuffer = self.bytes;

  for (NSInteger i = 0; i < self.length; i++) {
    [stringBuffer appendFormat:@"%02lX", (unsigned long)dataBuffer[i]];
  }

  return stringBuffer;
}

@end

#pragma mark - Persistent token (non-smartcard)

/// Persistent token implementation for Romanian eID cards.
/// Unlike smartcard tokens (ROCEICard), persistent tokens are registered with
/// macOS and persist across card removals. They use PKCS#11 to access the card
/// when needed.
///
/// The token is initialized with configuration data from ROCEIConnector.app
/// that includes:
/// - PKCS#11 module path and configuration directory
/// - Slot ID (0x1 for authentication, 0x2 for signing)
/// - Optionally: pre-fetched certificate and key metadata (for immediate
/// publishing)
@implementation ROCEIPersistentCard {
  TKTokenInstanceID _instanceID;
}

/// Extracts the JSON configuration dictionary from the token's configuration
/// data. This configuration is set by ROCEIConnector.app during token
/// registration.
- (NSDictionary *)connectorConfiguration {
  if (@available(macOS 10.15, *)) {
    NSData *data = self.configuration.configurationData;
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

/// Parses the PKCS#11 slot ID from the configuration dictionary.
/// Returns nil if slot is not configured or invalid.
- (nullable NSNumber *)configuredSlotFromDictionary:(NSDictionary *)config {
  NSString *slotString = config[@"slot"];
  if (![slotString isKindOfClass:[NSString class]] || slotString.length == 0) {
    return nil;
  }
  // Parse hex string (e.g., "0x1", "0x2") with error checking
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

/// Initializes a persistent token with the given instance ID.
/// This method is called by CryptoTokenKit when a persistent token
/// configuration is loaded.
///
/// Initialization process:
/// 1. Try to use pre-fetched certificate from configurationData (fast path, no
/// PKCS#11 needed)
/// 2. If not available, fall back to PKCS#11 enumeration to find public key
/// 3. Use cached certificate if available from previous card insertion
/// 4. Publish keychain items so macOS can use them for authentication
///
/// @param tokenDriver The token driver instance
/// @param instanceID Unique instance ID for this token (e.g., "rocei-pkcs11")
/// @param error Optional error output
- (instancetype)initWithTokenDriver:(TKTokenDriver *)tokenDriver
                         instanceID:(TKTokenInstanceID)instanceID
                              error:(NSError **)error {
  if (self = [super initWithTokenDriver:tokenDriver instanceID:instanceID]) {
    _instanceID = [instanceID copy];
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard init instanceID=%{public}@",
           _instanceID);

    NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray array];
    NSDictionary *config = [self connectorConfiguration];

    // Fast path: Use certificate from configurationData (pre-fetched by
    // ROCEIConnector via XPC helper) This allows immediate token publishing
    // without requiring card access or PIN entry
    NSString *certDERBase64 = config[@"certificateDER"];
    NSString *keyIDBase64 = config[@"keyID"];
    NSString *pubKeyDataBase64 = config[@"publicKeyData"];
    NSNumber *keySizeBitsNum = config[@"keySizeBits"];

    if ([certDERBase64 isKindOfClass:[NSString class]] &&
        certDERBase64.length > 0 &&
        [keyIDBase64 isKindOfClass:[NSString class]] &&
        keyIDBase64.length > 0) {

      // Decode base64-encoded certificate and key metadata
      NSData *certDER =
          [[NSData alloc] initWithBase64EncodedString:certDERBase64 options:0];
      NSData *keyID = [[NSData alloc] initWithBase64EncodedString:keyIDBase64
                                                          options:0];
      NSData *pubKeyData =
          [pubKeyDataBase64 isKindOfClass:[NSString class]] &&
                  pubKeyDataBase64.length > 0
              ? [[NSData alloc] initWithBase64EncodedString:pubKeyDataBase64
                                                    options:0]
              : nil;
      NSInteger keySizeBits = [keySizeBitsNum isKindOfClass:[NSNumber class]]
                                  ? keySizeBitsNum.integerValue
                                  : 384;

      os_log(OS_LOG_DEFAULT,
             "ROCEIPersistentCard: Using certificate from configurationData "
             "(%lu bytes)",
             (unsigned long)certDER.length);

      // Create SecCertificateRef from DER data
      SecCertificateRef certRef =
          SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certDER);
      if (certRef) {
        // Create keychain key item - this makes the key available to macOS
        // Security framework
        TKTokenKeychainKey *keyItem =
            [[TKTokenKeychainKey alloc] initWithCertificate:certRef
                                                   objectID:keyID];
        keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom; // EC key type
        keyItem.keySizeInBits = keySizeBits; // 256 or 384 bits
        keyItem.publicKeyData =
            pubKeyData; // Uncompressed EC point (0x04 || X || Y)
        keyItem.label = @"RO CEI Authentication Key";
        keyItem.canSign = YES;          // Enable signing operations
        keyItem.suitableForLogin = YES; // Allow use for macOS login

        // Set constraint: signing requires PIN authentication
        NSMutableDictionary<NSNumber *, TKTokenOperationConstraint>
            *constraints = [NSMutableDictionary dictionary];
        constraints[@(TKTokenOperationSignData)] = ROCEIConstraintPIN;
        keyItem.constraints = constraints;
        [items addObject:keyItem];

        // Create certificate item - this makes the certificate available to
        // applications
        TKTokenKeychainCertificate *certItem =
            [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef
                                                           objectID:keyID];
        certItem.label = @"RO CEI Authentication Certificate";
        [items addObject:certItem];

        CFRelease(certRef);
        os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard: Created key and cert "
                               "items from configurationData");
      }
    }

    // Fallback path: Enumerate via PKCS#11 if certificate not in configuration
    // This is slower but works if configurationData wasn't set or is incomplete
    if (items.count == 0) {
      // Initialize PKCS#11 module using configuration or fallback to bundle
      // resources
      NSError *pkcs11Error = nil;
      NSString *modulePath =
          [config[@"modulePath"] isKindOfClass:[NSString class]]
              ? config[@"modulePath"]
              : nil;
      NSString *configDir =
          [config[@"configDir"] isKindOfClass:[NSString class]]
              ? config[@"configDir"]
              : nil;
      os_log(OS_LOG_DEFAULT,
             "ROCEIPersistentCard: Falling back to PKCS#11 enumeration "
             "modulePath=%{public}@",
             modulePath ?: @"(nil)");

      PKCS11Module *module = nil;
      if (modulePath.length > 0) {
        // Use configured module path (usually IDplugManager's PKCS#11 library)
        module = [PKCS11Module sharedModuleWithPath:modulePath configDirectory:
            configDir];
      } else {
        // Fallback: try to find module in bundle resources (shouldn't happen
        // for persistent tokens)
        module = [[PKCS11Module alloc] initWithBundleResourcePath:
            [[NSBundle mainBundle] resourcePath]];
      }

      // Mark module as in-use to prevent concurrent teardown while enumerating
      [module beginUse];

      // Determine which slot to use (from config or auto-detect)
      NSNumber *slot = [self configuredSlotFromDictionary:config];
      if (slot == nil) {
        // Auto-detect first available slot (requires card to be inserted)
        slot = [module firstTokenSlot:&pkcs11Error];
      }

      // Open PKCS#11 session (read-only, no PIN needed for public key
      // enumeration)
      CK_SESSION_HANDLE session = 0;
      NSData *pubKeyId = nil;
      NSData *pubEcPoint = nil;
      NSNumber *pubBits = nil;

      // Find public EC key with "Authentication" label
      // This reads public key data without requiring PIN authentication
      if (slot != nil &&
          [module openSessionOnSlot:(uint32_t)slot.unsignedIntValue
                            session:&session
                              error:&pkcs11Error] &&
          [module
              findPublicECKeyWithLabelSubstring:@"Public Key ECC Authentication"
                                        session:session
                                       keyIdOut:&pubKeyId
                                     ecPointOut:&pubEcPoint
                                 keySizeBitsOut:&pubBits
                                          error:&pkcs11Error]) {

        // Close session after reading public key data
        [module closeSession:session error:nil];
        [module endUse];

        // Try to use cached certificate from previous card insertion
        // This allows immediate token publishing even if card was removed and
        // re-inserted IMPORTANT: Validate that cached cert matches current
        // card's key to prevent mismatch on card swap
        NSData *cachedCertDER = ROCEIReadCachedFile(@"auth_cert.der");
        id certificate = nil;
        if (cachedCertDER.length > 0) {
          // Validate cached certificate by comparing its public key with
          // current card's key
          SecCertificateRef certRef = SecCertificateCreateWithData(
              kCFAllocatorDefault, (CFDataRef)cachedCertDER);
          if (certRef) {
            SecKeyRef cachedPubKey = SecCertificateCopyKey(certRef);
            if (cachedPubKey && pubEcPoint) {
              // Compare public key data from certificate with public key from
              // card
              CFDataRef cachedPubKeyData =
                  SecKeyCopyExternalRepresentation(cachedPubKey, NULL);
              if (cachedPubKeyData) {
                // Both are uncompressed EC points (04 || X || Y)
                if ([(__bridge NSData *)cachedPubKeyData
                        isEqualToData:pubEcPoint]) {
                  certificate = CFBridgingRelease(certRef);
                  os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard: Using validated "
                                         "cached certificate");
                } else {
                  os_log(OS_LOG_DEFAULT,
                         "ROCEIPersistentCard: Cached cert public key mismatch "
                         "- card was swapped, discarding cache");
                  CFRelease(certRef);
                }
                CFRelease(cachedPubKeyData);
              } else {
                CFRelease(certRef);
              }
              if (cachedPubKey)
                CFRelease(cachedPubKey);
            } else {
              CFRelease(certRef);
            }
          }
        }

        TKTokenKeychainKey *keyItem = nil;
        if (certificate != NULL) {
          // Full keychain item with certificate (preferred)
          keyItem = [[TKTokenKeychainKey alloc]
              initWithCertificate:(__bridge SecCertificateRef)certificate
                         objectID:pubKeyId];
          TKTokenKeychainCertificate *certificateItem =
              [[TKTokenKeychainCertificate alloc]
                  initWithCertificate:(__bridge SecCertificateRef)certificate
                             objectID:pubKeyId];
          certificateItem.label = @"RO CEI Authentication Certificate";
          [items addObject:certificateItem];
        } else {
          // Key-only item (certificate will be cached on first PIN entry)
          keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:NULL
                                                           objectID:pubKeyId];
          keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom;
          keyItem.keySizeInBits = pubBits ? pubBits.integerValue : 384;
          keyItem.publicKeyData = pubEcPoint; // Uncompressed EC point
          os_log(
              OS_LOG_DEFAULT,
              "ROCEIPersistentCard: publishing key-only item (no cached cert)");
        }

        // Configure key capabilities
        keyItem.label = @"RO CEI Authentication Key";
        keyItem.canSign = YES;
        keyItem.suitableForLogin = YES;

        // Set constraint: signing requires PIN
        NSMutableDictionary<NSNumber *, TKTokenOperationConstraint>
            *constraints = [NSMutableDictionary dictionary];
        constraints[@(TKTokenOperationSignData)] = ROCEIConstraintPIN;
        keyItem.constraints = constraints;
        [items addObject:keyItem];
      } else {
        // Close session on error
        if (session != 0) {
          [module closeSession:session error:nil];
        }
        [module endUse];
        os_log_error(
            OS_LOG_DEFAULT,
            "ROCEIPersistentCard: PKCS#11 enumeration failed (%{public}@)",
            pkcs11Error.localizedDescription);
      }
    }

    // Publish keychain items to macOS
    // For persistent tokens (TKToken), the system manages keychain access
    // automatically Items are registered with the Security framework and become
    // available to applications
    if (@available(macOS 10.15, *)) {
      if (self.configuration != nil && items.count > 0) {
        self.configuration.keychainItems = items;
        os_log(OS_LOG_DEFAULT,
               "ROCEIPersistentCard set configuration.keychainItems with %lu "
               "items",
               (unsigned long)items.count);
      } else if (items.count == 0) {
        os_log_error(OS_LOG_DEFAULT,
                     "ROCEIPersistentCard has no keychain items to configure");
      } else {
        os_log_error(OS_LOG_DEFAULT,
                     "ROCEIPersistentCard configuration is nil");
      }
    }
  }
  return self;
}

/// Creates a token session for handling cryptographic operations.
/// Called by CryptoTokenKit when an application requests token access.
///
/// @param token The persistent token instance
/// @param error Optional error output
/// @return A new ROCEIPersistentSession instance
- (TKTokenSession *)token:(TKToken *)token
    createSessionWithError:(NSError *_Nullable __autoreleasing *)error {
  os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard createSession");
  return [[ROCEIPersistentSession alloc] initWithToken:self];
}

@end

@implementation ROCEIKeychainKey

/// Designated initializer for Romanian eID keychain keys.
///
/// @param certificateRef The X.509 certificate associated with this key
/// @param objectID Unique identifier for the key (typically CKA_ID from PKCS#11)
/// @param certificateID Object ID of the associated certificate
/// @param alwaysAuthenticate Whether to require PIN for every operation (YES) or
/// allow caching (NO)
/// @return Initialized key instance
- (instancetype)initWithCertificate:(SecCertificateRef)certificateRef
                           objectID:(TKTokenObjectID)objectID
                      certificateID:(TKTokenObjectID)certificateID
                 alwaysAuthenticate:(BOOL)alwaysAuthenticate {
  if (self = [super initWithCertificate:certificateRef objectID:objectID]) {
    _certificateID = certificateID;
    _alwaysAuthenticate = alwaysAuthenticate;
  }
  return self;
}

/// Returns the PIV key reference byte from the object ID.
/// @return Key reference tag (single byte)
- (UInt8)keyID {
  return [self.objectID unsignedCharValue];
}

/// Returns the PIV algorithm identifier for this key per SP 800-78-4.
/// @return Algorithm ID byte: 0x11 (EC P-256), 0x14 (EC P-384), 0x06 (RSA
/// 1024), 0x07 (RSA 2048), or 0 for unknown
- (UInt8)algID {
  // SP 800-78-4 Table 6-2 and 6-3
  if ([self.keyType isEqual:(id)kSecAttrKeyTypeECSECPrimeRandom]) {
    switch (self.keySizeInBits) {
    case 256:
      return 0x11; // EC 256
    case 384:
      return 0x14; // EC 384
    }
  } else if ([self.keyType isEqual:(id)kSecAttrKeyTypeRSA]) {
    switch (self.keySizeInBits) {
    case 1024:
      return 0x06; // RSA 1024
    case 2048:
      return 0x07; // RSA 2048
    }
  }
  return 0;
}

@end

@implementation TKTokenKeychainItem (ROCEIDataFormat)

/// Sets a user-friendly name for the keychain item by prepending it to the
/// existing label. If the item already has a label, the name is prepended with
/// the format "name (label)".
///
/// @param name The user-friendly name to set
- (void)setName:(NSString *)name {
  if (self.label != nil) {
    self.label = [NSString stringWithFormat:@"%@ (%@)", name, self.label];
  } else {
    self.label = name;
  }
}

@end

@implementation TKSmartCard (ROCEIDataFormat)

/// Sends an APDU command with optional TLV request data and validates the
/// response tag. This is a high-level wrapper around the base sendIns:p1:p2:data:le:sw:error:
/// method that handles TLV encoding/decoding and tag validation.
///
/// @param ins Instruction byte (INS)
/// @param p1 Parameter 1 byte (P1)
/// @param p2 Parameter 2 byte (P2)
/// @param request Optional TLV record containing request data
/// @param expectedTag Expected tag in the response TLV
/// @param sw Output parameter for status word (SW1||SW2)
/// @param error Optional error output
/// @return Parsed TLV record with the expected tag, or nil on error
- (TKTLVRecord *)sendIns:(UInt8)ins
                      p1:(UInt8)p1
                      p2:(UInt8)p2
                 request:(TKTLVRecord *)request
             expectedTag:(TKTLVTag)expectedTag
                      sw:(UInt16 *)sw
                   error:(NSError *_Nullable __autoreleasing *)error {
  *sw = 0;
  NSData *replyData = [self sendIns:ins
                                 p1:p1
                                 p2:p2
                               data:request.data
                                 le:@0
                                 sw:sw
                              error:error];
  if (replyData.length == 0) {
    if (error != nil && replyData != nil &&
        (*sw == 0x9000 || *sw == 0x6a82 || *sw == 0x6a80)) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeObjectNotFound
                               userInfo:nil];
    }
    return nil;
  }

  TKTLVRecord *response = [TKBERTLVRecord recordFromData:replyData];
  if (response.tag != expectedTag) {
    os_log_error(OS_LOG_DEFAULT, "expecting response with tag 0x%x, got %@",
                 (unsigned)expectedTag, response);
    if (error != nil) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeCorruptedData
                               userInfo:nil];
    }
    return nil;
  }

  return response;
}

/// Reads all TLV records associated with a particular token object.
/// This method retrieves the complete set of TLV data for a given object ID.
///
/// @param objectID The object identifier (must be NSData)
/// @param error Optional error output
/// @return Array of TLV records, or nil on error
- (nullable NSArray<TKTLVRecord *> *)recordsOfObject:(TKTokenObjectID)objectID
                                               error:(NSError **)error {
  if (![objectID isKindOfClass:NSData.class]) {
    if (error != nil) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeObjectNotFound
                               userInfo:nil];
    }
    return nil;
  }

  os_log_debug(OS_LOG_DEFAULT, "reading card object %@", objectID);
  TKTLVRecord *request =
      [[TKBERTLVRecord alloc] initWithTag:0x5c value:(NSData *)objectID];
  UInt16 sw;
  TKTLVRecord *response = [self sendIns:0xcb
                                     p1:0x3f
                                     p2:0xff
                                request:request
                            expectedTag:0x53
                                     sw:&sw
                                  error:error];
  if (response == nil) {
    return nil;
  }

  NSArray<TKTLVRecord *> *records =
      [TKBERTLVRecord sequenceOfRecordsFromData:response.value];
  if (records == nil) {
    os_log_error(OS_LOG_DEFAULT, "read data object has incorrect structure");
    if (error != nil) {
      *error = [NSError errorWithDomain:TKErrorDomain
                                   code:TKErrorCodeCorruptedData
                               userInfo:nil];
    }
  }
  return records;
}

@end

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration
      // is active

@implementation ROCEICard

- (nullable NSData *)dataOfCertificate:(TKTokenObjectID)certificateObjectID smartCard:(TKSmartCard *)smartCard error:(NSError * _Nullable __autoreleasing *)error {
    // Read certificate records from the card.
    NSArray<TKTLVRecord *> *certificateRecords = [smartCard recordsOfObject:certificateObjectID error:error];
    if (certificateRecords == nil) {
        return nil;
    }

    // Process certificate records, extract data and info field.
    __block NSData *certificateData;
    __block BOOL compressed = NO;
    [certificateRecords enumerateObjectsUsingBlock:^(TKTLVRecord * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if (obj.tag == 0x70) {
            certificateData = obj.value;
        } else if (obj.tag == 0x71 && obj.value.length > 0) {
            UInt8 info = *(const UInt8 *)obj.value.bytes;
            if ((info & 0x01) != 0) {
                compressed = YES;
            }
        }
    }];
    if (certificateData == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeObjectNotFound userInfo:nil];
        }
        return nil;
    }

    return compressed ? [certificateData inflate] : certificateData;
}

- (BOOL)populateIdentityFromSmartCard:(TKSmartCard *)smartCard into:(NSMutableArray<TKTokenKeychainItem *> *)items certificateTag:(TKTLVTag)certificateTag name:(NSString *)certificateName keyTag:(TKTLVTag)keyTag name:(NSString *)keyName sign:(BOOL)sign keyManagement:(BOOL)keyManagement alwaysAuthenticate:(BOOL)alwaysAuthenticate error:(NSError **)error {
    // Read certificate data.
    TKTokenObjectID certificateID = [TKBERTLVRecord dataForTag:certificateTag];
    NSData *certificateData = [self dataOfCertificate:certificateID smartCard:smartCard error:error];
    if (certificateData == nil) {
        // If certificate cannot be found, just silently skip the operation, otherwise report an error.
        return (error != nil && [(*error).domain isEqual:TKErrorDomain] && (*error).code == TKErrorCodeObjectNotFound);
    }

    // Create certificate item.
    id certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certificateData));
    if (certificate == NULL) {
        if (error != nil) {
            *error = [NSError errorWithDomain:TKErrorDomain code:TKErrorCodeCorruptedData userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"CORRUPTED_CERT", nil)}];
        }
        return NO;
    }
    TKTokenKeychainCertificate *certificateItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:certificateID];
    if (certificateItem == nil) {
        return NO;
    }
    [certificateItem setName:certificateName];

    // Create key item.
    TKTokenKeychainKey *keyItem = [[ROCEIKeychainKey alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:@(keyTag) certificateID:certificateItem.objectID alwaysAuthenticate:alwaysAuthenticate];
    if (keyItem == nil) {
        return NO;
    }
    [keyItem setName:keyName];

    NSMutableDictionary<NSNumber *, TKTokenOperationConstraint> *constraints = [NSMutableDictionary dictionary];
    keyItem.canSign = sign;
    keyItem.suitableForLogin = sign;
    TKTokenOperationConstraint constraint = alwaysAuthenticate ? ROCEIConstraintPINAlways : ROCEIConstraintPIN;
    if (sign) {
        constraints[@(TKTokenOperationSignData)] = constraint;
    }
    if ([keyItem.keyType isEqual:(id)kSecAttrKeyTypeRSA]) {
        keyItem.canDecrypt = keyManagement;
        if (keyManagement) {
            constraints[@(TKTokenOperationDecryptData)] = constraint;
        }
    } else if ([keyItem.keyType isEqual:(id)kSecAttrKeyTypeECSECPrimeRandom]) {
        keyItem.canPerformKeyExchange = keyManagement;
        if (keyManagement) {
            constraints[@(TKTokenOperationPerformKeyExchange)] = constraint;
        }
    }
    keyItem.constraints = constraints;
    [items addObject:certificateItem];
    [items addObject:keyItem];
    return YES;
}

/// Initializes a smartcard-based token when a Romanian eID card is inserted.
/// This is called by CryptoTokenKit when a card matching the AID is detected.
///
/// Architecture note: We use PKCS#11 to access the Romanian eID card because OpenSC
/// doesn't support it natively. CryptoTokenKit still provides TKSmartCard + AID for
/// card insertion/matching, but we use PKCS#11 for all cryptographic operations.
///
/// @param smartCard The TKSmartCard instance provided by CryptoTokenKit
/// @param AID Application ID (may be nil if not preselected)
/// @param tokenDriver The token driver instance
/// @param error Optional error output
- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID PIVDriver:(ROCEIDriver *)tokenDriver error:(NSError **)error {
    // Generate unique instance ID for this card insertion
    NSString *instanceID = [NSUUID UUID].UUIDString;
    os_log(OS_LOG_DEFAULT, "Extension: Card initWithSmartCard AID=%{public}@", AID ? AID : (NSData *)@"(nil)");

    // If AID was not preselected by CryptoTokenKit, try selecting it manually
    // Romanian eID AID: E828BD080FD25047656E65726963
    // P2=0x0C selects by name (as opposed to P2=0x04 which selects by partial AID)
    if (AID == nil) {
        NSData *roceiAID = [self.class roceiDataFromHexString:@"E828BD080FD25047656E65726963"];
        if (roceiAID.length > 0) {
            // Open smartcard session for APDU transmission
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            __block BOOL sessionOK = NO;
            [smartCard beginSessionWithReply:^(BOOL success, NSError * _Nullable sessionError) {
                sessionOK = success;
                dispatch_semaphore_signal(sem);
            }];
            dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
            if (sessionOK) {
                // Build SELECT APDU: CLA=0x00 INS=0xA4 P1=0x04 P2=0x0C Lc=<AID length> <AID> Le=0x00
                NSMutableData *apdu = [NSMutableData dataWithCapacity:(6 + roceiAID.length)];
                uint8_t header[] = {0x00, 0xA4, 0x04, 0x0C, (uint8_t)roceiAID.length};
                [apdu appendBytes:header length:sizeof(header)];
                [apdu appendData:roceiAID];
                uint8_t le = 0x00;  // Expected response length (0 = maximum)
                [apdu appendBytes:&le length:1];

                // Transmit SELECT APDU
                dispatch_semaphore_t apduSem = dispatch_semaphore_create(0);
                __block NSData *response = nil;
                [smartCard transmitRequest:apdu reply:^(NSData * _Nullable responseData, NSError * _Nullable apduError) {
                    response = responseData;
                    dispatch_semaphore_signal(apduSem);
                }];
                dispatch_semaphore_wait(apduSem, DISPATCH_TIME_FOREVER);

                // Check status word (SW1 SW2)
                if (response.length >= 2) {
                    const unsigned char *bytes = response.bytes;
                    UInt8 sw1 = bytes[response.length - 2];
                    UInt8 sw2 = bytes[response.length - 1];
                    os_log(OS_LOG_DEFAULT, "Extension: Card manual SELECT AID SW=%02X%02X", sw1, sw2);
                    // 0x9000 = success, other values indicate error
                }
                [smartCard endSession];
            }
        }
    }

    // Initialize token with smartcard and enumerate keychain items
    if (self = [super initWithSmartCard:smartCard AID:AID instanceID:instanceID tokenDriver:tokenDriver]) {
        NSMutableArray<TKTokenKeychainItem *> *items = [NSMutableArray array];

        // Initialize PKCS#11 module (uses bundle resources for smartcard tokens)
        NSError *pkcs11Error = nil;
        PKCS11Module *module = [[PKCS11Module alloc] initWithBundleResourcePath:[[NSBundle mainBundle] resourcePath]];

        // Mark module as in-use to prevent concurrent teardown
        [module beginUse];

        NSNumber *slot = [module firstTokenSlot:&pkcs11Error];

        // Log supported mechanisms so we can determine if ECDH is available for macOS pairing
        if (slot != nil) {
            [module logMechanismsForSlot:(CK_SLOT_ID)slot.unsignedLongValue];
        }

        // Enumerate public key and certificate from PKCS#11 (both are public objects, no PIN required)
        CK_SESSION_HANDLE session = 0;
        NSData *pubKeyId = nil;
        NSData *pubEcPoint = nil;
        NSNumber *pubBits = nil;

        if (slot != nil &&
            [module openSessionOnSlot:(uint32_t)slot.unsignedIntValue session:&session error:&pkcs11Error] &&
            [module findPublicECKeyWithLabelSubstring:@"Public Key ECC Authentication"
                                              session:session
                                             keyIdOut:&pubKeyId
                                           ecPointOut:&pubEcPoint
                                        keySizeBitsOut:&pubBits
                                                error:&pkcs11Error]) {

            // Read certificate directly from the card while session is open.
            // Certificates are public objects — no PIN required.
            // This ensures the "unpaired certificate" notification fires on first insertion.
            NSData *freshCertDER = [module readCertificateDERWithLabelSubstring:@"Certificate ECC Authentication"
                                                                        session:session
                                                                          error:nil];

            // Close session after reading all public data
            [module closeSession:session error:nil];
            [module endUse];

            // Cache fresh cert so subsequent insertions are immediate (no re-read needed)
            if (freshCertDER.length > 0) {
                ROCEIWriteCachedFile(@"auth_cert.der", freshCertDER, NULL);
            }

            // Use fresh cert, fall back to previously cached cert if card read failed
            NSData *certDER = freshCertDER.length > 0 ? freshCertDER : ROCEIReadCachedFile(@"auth_cert.der");
            id certificate = nil;

            if (certDER.length > 0) {
                // If using cached cert (not fresh), validate it matches the current card's public key
                if (freshCertDER.length == 0) {
                    SecCertificateRef certRef = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certDER);
                    if (certRef) {
                        SecKeyRef cachedPubKey = SecCertificateCopyKey(certRef);
                        if (cachedPubKey) {
                            CFDataRef cachedPubKeyData = SecKeyCopyExternalRepresentation(cachedPubKey, NULL);
                            if (cachedPubKeyData && [(__bridge NSData *)cachedPubKeyData isEqualToData:pubEcPoint]) {
                                certificate = CFBridgingRelease(certRef);
                                os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard: Using validated cached certificate (fallback)");
                            } else {
                                os_log(OS_LOG_DEFAULT, "ROCEIPersistentCard: Cached cert public key mismatch on fallback - card was swapped, discarding cache");
                                CFRelease(certRef);
                            }
                            if (cachedPubKeyData) CFRelease(cachedPubKeyData);
                            CFRelease(cachedPubKey);
                        } else {
                            CFRelease(certRef);
                        }
                    }
                } else {
                    // Fresh cert from card - use it directly without validation
                    certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certDER));
                }
            }

            TKTokenKeychainKey *keyItem = nil;
            if (certificate != NULL) {
                // Full keychain item with certificate — triggers macOS "unpaired certificate" notification
                keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:pubKeyId];
                // Always set publicKeyData explicitly so ctkahp can compute the public key hash
                // (used for hintsForToken key 0 — without it the "Unpaired certificate" notification
                //  is suppressed because macOS cannot extract the key from IDEMIA's cert encoding)
                keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom;
                keyItem.keySizeInBits = pubBits ? pubBits.integerValue : 384;
                keyItem.publicKeyData = pubEcPoint;

                TKTokenObjectID certObjectID = pubKeyId; // same ID as key so macOS links them as an identity
                TKTokenKeychainCertificate *certificateItem = [[TKTokenKeychainCertificate alloc] initWithCertificate:(__bridge SecCertificateRef)certificate objectID:certObjectID];
                certificateItem.label = @"RO CEI Authentication Certificate";
                [items addObject:certificateItem];
            } else {
                // Key-only fallback (cert unreadable — will be cached after first sign)
                keyItem = [[TKTokenKeychainKey alloc] initWithCertificate:NULL objectID:pubKeyId];
                keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom;
                if (pubBits != nil) {
                    keyItem.keySizeInBits = pubBits.integerValue;
                }
                keyItem.publicKeyData = pubEcPoint;
                os_log(OS_LOG_DEFAULT, "Extension: Card publishing key-only item (certificate unreadable)");
            }

            keyItem.label = @"RO CEI Authentication Key";
            keyItem.canSign = YES;
            keyItem.suitableForLogin = YES;
            keyItem.canPerformKeyExchange = YES;  // Enables ECDH key exchange (TKTokenOperationPerformKeyExchange)
            keyItem.canDecrypt = YES;             // Enables canDecrypt so ctkbind finds this key as a wrap key via keychain attributes

            NSMutableDictionary<NSNumber *, TKTokenOperationConstraint> *constraints = [NSMutableDictionary dictionary];
            constraints[@(TKTokenOperationSignData)] = ROCEIConstraintPIN;
            constraints[@(TKTokenOperationPerformKeyExchange)] = ROCEIConstraintPIN;
            constraints[@(TKTokenOperationDecryptData)] = ROCEIConstraintPIN;
            keyItem.constraints = constraints;

            [items addObject:keyItem];
        } else {
            if (session != 0) {
                [module closeSession:session error:nil];
            }
            [module endUse];
            os_log_error(OS_LOG_DEFAULT, "Extension: Card failed to enumerate public key via PKCS#11 — not a CEI card (%{public}@)", pkcs11Error.localizedDescription);
            // Return nil so ctkd skips to the next extension.
            // This is essential when running as catch-all (no AID declared): without this,
            // we'd claim every inserted card even if PKCS#11 can't access it.
            if (error) {
                *error = [NSError errorWithDomain:TKErrorDomain
                                            code:TKErrorCodeObjectNotFound
                                        userInfo:@{NSLocalizedDescriptionKey: @"Not a Romanian eID card"}];
            }
            return nil;
        }

        // Publish keychain items to macOS
        // For smartcard tokens (TKSmartCardToken), items are added to keychainContents
        [self.keychainContents fillWithItems:items];
    }

    return self;
}

/// Converts a hexadecimal string to binary data.
/// Strips non-hex characters before conversion.
///
/// @param hexString String containing hexadecimal digits (e.g.,
/// "E828BD080FD25047656E65726963")
/// @return Binary data parsed from the hex string
+ (NSData *)roceiDataFromHexString:(NSString *)hexString {
    NSString *clean = [[hexString componentsSeparatedByCharactersInSet:
                        [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet]]
                       componentsJoinedByString:@""];
    NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
    unsigned char byte = 0;
    for (NSUInteger i = 0; i + 1 < clean.length; i += 2) {
        NSString *pair = [clean substringWithRange:NSMakeRange(i, 2)];
/// Creates a token session for handling cryptographic operations.
/// Called by CryptoTokenKit when an application needs to use the token.
///
/// @param token The token instance (unused parameter for compatibility)
/// @param error Optional error output
/// @return A new session instance for handling operations
        byte = (unsigned char)strtoul(pair.UTF8String, NULL, 16);
        [data appendBytes:&byte length:1];
    }
    return data;
}

- (TKTokenSession *)token:(TKToken *)token createSessionWithError:(NSError * _Nullable __autoreleasing *)error {
    return [[ROCEISession alloc] initWithToken:self];
}

@end
#endif // DISABLED: smartcard mode
