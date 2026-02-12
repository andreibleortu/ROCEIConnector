//
// PKCS11.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//

#pragma once

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>

#include "pkcs11_min.h"

NS_ASSUME_NONNULL_BEGIN

// ---------------------------------------------------------------------------
// Shared constants for library discovery
// ---------------------------------------------------------------------------

/// Filename of the IDEMIA PKCS#11 dynamic library.
static NSString *const kPKCS11LibraryName = @"libidplug-pkcs11.dylib";

/// Application Support sub-directory used for a cached copy of the library.
static NSString *const kPKCS11AppSupportSubdir = @"com.andrei.rocei.connector";

/// Relative path from the main app bundle root to the appex Resources dir.
static NSString *const kPKCS11AppexSubpath =
    @"Contents/PlugIns/ROCEIExtension.appex/Contents/Resources";

/// Absolute path to the IDplugManager-supplied library.
static NSString *const kPKCS11IDplugManagerDir =
    @"/Applications/IDplugManager.app/Contents/Frameworks";

// ---------------------------------------------------------------------------
// Unified library path resolution
// ---------------------------------------------------------------------------

/// Returns the path to the IDplugManager-installed library.
static inline NSString *PKCS11IDplugManagerLibraryPath(void) {
  return [kPKCS11IDplugManagerDir
      stringByAppendingPathComponent:kPKCS11LibraryName];
}

/// Returns the Application Support cached-copy path.
static inline NSString *PKCS11AppSupportLibraryPath(void) {
  NSURL *appSupport = [[[NSFileManager defaultManager]
      URLsForDirectory:NSApplicationSupportDirectory
             inDomains:NSUserDomainMask] firstObject];
  return [[[appSupport URLByAppendingPathComponent:kPKCS11AppSupportSubdir]
      URLByAppendingPathComponent:kPKCS11LibraryName] path];
}

/// Searches for libidplug-pkcs11.dylib in a well-defined priority order that
/// works correctly regardless of which target (app, appex, helper) is running:
///
///   1. Current bundle's own Resources  (matches inside the .appex)
///   2. Appex Resources relative to current bundle  (matches from main app)
///   3. Parent-app's appex Resources  (matches from embedded helper/login item
///      at Contents/Library/LoginItems/)
///   4. ~/Library/Application Support cache
///   5. /Applications/IDplugManager.app
///
/// Duplicate paths are skipped so the function never stat()s the same file
/// twice.  Returns nil if the library is not found anywhere.
static inline NSString *_Nullable PKCS11FindLibraryPath(void) {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *bundle = [NSBundle mainBundle].bundlePath;

  NSArray<NSString *> *candidates = @[
    // 1. Own bundle Resources (appex: this IS the library location)
    [[[NSBundle mainBundle] resourcePath]
        stringByAppendingPathComponent:kPKCS11LibraryName],

    // 2. Appex inside current bundle (main app looks into its PlugIns)
    [[bundle stringByAppendingPathComponent:kPKCS11AppexSubpath]
        stringByAppendingPathComponent:kPKCS11LibraryName],

    // 3. Navigate up from embedded login-item helper:
    //    Helper.app → LoginItems/ → Library/ → Contents/ → PlugIns/…
    [[[[[[bundle
        stringByDeletingLastPathComponent]   // LoginItems
        stringByDeletingLastPathComponent]   // Library
        stringByDeletingLastPathComponent]   // Contents
        stringByAppendingPathComponent:@"PlugIns/ROCEIExtension.appex"]
        stringByAppendingPathComponent:@"Contents/Resources"]
        stringByAppendingPathComponent:kPKCS11LibraryName],

    // 4. Application Support (user-cached copy)
    PKCS11AppSupportLibraryPath(),

    // 5. IDplugManager installation
    PKCS11IDplugManagerLibraryPath(),
  ];

  NSMutableSet<NSString *> *seen = [NSMutableSet set];
  for (NSString *path in candidates) {
    if (!path || [seen containsObject:path]) continue;
    [seen addObject:path];
    if ([fm fileExistsAtPath:path]) return path;
  }
  return nil;
}

/// Returns the PKCS#11 configuration directory for a given library path.
/// The IDEMIA library expects its config files in the same directory as the
/// .dylib, so this is simply the parent directory.
static inline NSString *PKCS11ConfigDirectoryForPath(NSString *libraryPath) {
  return [libraryPath stringByDeletingLastPathComponent];
}

// ---------------------------------------------------------------------------
// Known-good library hashes (supply-chain gate)
// ---------------------------------------------------------------------------

/// Known-good SHA-512 hashes of libidplug-pkcs11.dylib.
/// Defined here so both the PKCS#11 wrapper (supply-chain gate before dlopen)
/// and the Connector GUI (user-visible version warning) share a single source
/// of truth.  Add new hashes when supporting additional IDplugManager versions.
static inline NSArray<NSString *> *PKCS11KnownGoodLibraryHashes(void) {
  static NSArray<NSString *> *hashes = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    hashes = @[
      // IDplugManager 4.5.0
      @"ceae559a728f558e4813e28a6d7cb2fccfc604dbe8312c453f801fd878481e1e"
       "dee3c048ec7b3cb7daaf169e8977c590a516fd792ae14397783bcaddaa39b928",
      // Add future IDplugManager version hashes here
    ];
  });
  return hashes;
}

// ---------------------------------------------------------------------------
// SHA-512 file hashing (shared implementation)
// ---------------------------------------------------------------------------

/// Compute SHA-512 hash of a file at the given path.
/// Returns a lowercase hex string, or nil if the file cannot be read.
///
/// Defined as static inline so each compilation target gets its own copy
/// without requiring a shared library or framework target.
static inline NSString *_Nullable PKCS11ComputeSHA512(NSString *path) {
  NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:path];
  if (!file)
    return nil;

  CC_SHA512_CTX ctx;
  CC_SHA512_Init(&ctx);

  NSData *data;
  while ((data = [file readDataOfLength:8192]).length > 0) {
    CC_SHA512_Update(&ctx, data.bytes, (CC_LONG)data.length);
  }
  [file closeFile];

  unsigned char digest[CC_SHA512_DIGEST_LENGTH];
  CC_SHA512_Final(digest, &ctx);

  NSMutableString *hash =
      [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
    [hash appendFormat:@"%02x", digest[i]];
  }
  return hash;
}

// Direct function pointer types for dlsym usage
typedef CK_RV (*PFN_C_Initialize)(void*);
typedef CK_RV (*PFN_C_Finalize)(void*);
typedef CK_RV (*PFN_C_GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV (*PFN_C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
typedef CK_RV (*PFN_C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO*);
typedef CK_RV (*PFN_C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*PFN_C_CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*PFN_C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*PFN_C_Logout)(CK_SESSION_HANDLE);
typedef CK_RV (*PFN_C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*PFN_C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
typedef CK_RV (*PFN_C_FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*PFN_C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*PFN_C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*PFN_C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*PFN_C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
typedef CK_RV (*PFN_C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (*PFN_C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

/// Securely clears sensitive data (e.g. PIN) from memory using memset_s to
/// prevent compiler optimization from eliding the clear.
FOUNDATION_EXTERN void PKCS11SecureClearData(NSMutableData *data);

@interface PKCS11Module : NSObject

/// Returns a shared singleton instance for the specified module path.
/// This ensures only one C_Initialize call per module across the process lifecycle.
+ (instancetype)sharedModuleWithPath:(NSString *)modulePath configDirectory:(nullable NSString *)configDirectory;

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithBundleResourcePath:(NSString *)bundleResourcePath;
/// Initializes with explicit PKCS#11 module path and config directory for CWD.
- (instancetype)initWithModulePath:(NSString *)modulePath configDirectory:(nullable NSString *)configDirectory;

/// Loads the PKCS#11 library (dlopen + SHA-512 verification + C_Initialize).
- (BOOL)loadAndInitialize:(NSError * _Nullable * _Nullable)error;

/// Calls C_Finalize to close all sessions and shut down the library.
/// Clears the shared module cache so the next use will re-initialize.
- (BOOL)finalizeAndReset:(NSError * _Nullable * _Nullable)error;

/// Removes all modules from the shared module cache.
/// Modules with active users (beginUse without matching endUse) are skipped.
+ (void)clearSharedModuleCache;

/// Marks this module as in-use.  Call before any sequence of PKCS#11 operations
/// (open session, login, sign, etc.) to prevent finalizeAndReset: from tearing
/// down the library while operations are in flight.
/// Must be balanced by a call to endUse when the operation sequence completes.
- (void)beginUse;

/// Marks one use of this module as complete.  When the last active user calls
/// endUse, finalizeAndReset: (if waiting) is unblocked.
- (void)endUse;

/// Current number of active users (diagnostic).
@property(nonatomic, readonly) int activeUseCount;

/// YES if the module has been poisoned by a timeout.  All operations except
/// finalizeAndReset: will immediately fail.  Call finalizeAndReset: (which
/// runs C_Finalize to hard-close every session) to clear the flag and allow
/// the module to be re-initialized.
@property(nonatomic, readonly, getter=isPoisoned) BOOL poisoned;

/// Returns the first slot that currently has a token present.
- (nullable NSNumber *)firstTokenSlot:(NSError * _Nullable * _Nullable)error;

/// Opens a session on a slot.
- (BOOL)openSessionOnSlot:(uint32_t)slot session:(CK_SESSION_HANDLE *)outSession error:(NSError * _Nullable * _Nullable)error;

/// Closes a session.
- (BOOL)closeSession:(CK_SESSION_HANDLE)session error:(NSError * _Nullable * _Nullable)error;

/// Logs in as CKU_USER.
/// @param session The PKCS#11 session handle
/// @param pinData The PIN as NSMutableData (will NOT be cleared by this method — caller manages lifetime)
/// @param error Output error if login fails.  Detailed messages for CKR_PIN_INCORRECT and CKR_PIN_LOCKED.
/// @return YES if login succeeded, NO otherwise
- (BOOL)loginUserOnSession:(CK_SESSION_HANDLE)session pinData:(NSMutableData *)pinData error:(NSError * _Nullable * _Nullable)error;

/// Logs out from a PKCS#11 session (calls C_Logout).
/// Should be called before closing a session to properly clear authentication state.
- (BOOL)logoutSession:(CK_SESSION_HANDLE)session error:(NSError * _Nullable * _Nullable)error;

/// Finds the first X.509 certificate matching label substring (case-sensitive).
- (nullable NSData *)readCertificateDERWithLabelSubstring:(NSString *)labelSubstring
                                                 session:(CK_SESSION_HANDLE)session
                                                   error:(NSError * _Nullable * _Nullable)error;

/// Finds a public EC key by label substring and returns its CKA_ID and EC_POINT.
/// EC_POINT is returned as uncompressed point (0x04 || X || Y).
- (BOOL)findPublicECKeyWithLabelSubstring:(NSString *)labelSubstring
                                  session:(CK_SESSION_HANDLE)session
                                 keyIdOut:(NSData * _Nullable * _Nullable)outKeyId
                               ecPointOut:(NSData * _Nullable * _Nullable)outEcPoint
                            keySizeBitsOut:(NSNumber * _Nullable * _Nullable)outKeySizeBits
                                    error:(NSError * _Nullable * _Nullable)error;

/// Finds the first private key matching CKA_ID (raw bytes).
- (BOOL)findPrivateKeyById:(NSData *)ckaId
                   session:(CK_SESSION_HANDLE)session
                 objectOut:(CK_OBJECT_HANDLE *)outKey
                     error:(NSError * _Nullable * _Nullable)error;

/// Signs with ECDSA (CKM_ECDSA expects digest input).
/// Returns raw signature r||s (token output) in `outSignature`.
/// Protected by a 60-second timeout; returns an error on timeout.
- (BOOL)ecdsaSignWithSession:(CK_SESSION_HANDLE)session
                 privateKey:(CK_OBJECT_HANDLE)key
                      digest:(NSData *)digest
                signatureOut:(NSData * _Nullable * _Nullable)outSignature
                       error:(NSError * _Nullable * _Nullable)error;

/// Performs ECDH key exchange (CKM_ECDH1_DERIVE + CKD_NULL) and returns the raw shared secret.
/// The session must already be logged in. The returned bytes are the X coordinate of the
/// shared EC point (the "Z" value), keySizeBytes long (32 for P-256, 48 for P-384).
///
/// @param session Authenticated PKCS#11 session handle
/// @param privateKey Private key object handle (the card's EC private key)
/// @param pubKeyData Other party's EC public key as uncompressed point (04 || X || Y)
/// @param keySizeBytes Expected shared secret length in bytes (= field size, e.g. 48 for P-384)
- (nullable NSData *)ecdhDeriveWithSession:(CK_SESSION_HANDLE)session
                                privateKey:(CK_OBJECT_HANDLE)privateKey
                         otherPublicKeyData:(NSData *)pubKeyData
                              keySizeBytes:(NSUInteger)keySizeBytes
                                     error:(NSError * _Nullable * _Nullable)error;

/// Logs all mechanisms supported by the given slot (diagnostic only).
/// Specifically calls out CKM_ECDH1_DERIVE if present (needed for macOS smart card pairing).
- (void)logMechanismsForSlot:(CK_SLOT_ID)slot;

@end

NS_ASSUME_NONNULL_END
