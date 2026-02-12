//
// PKCS11.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//

// PKCS#11 API patterns legitimately pass NULL where Objective-C annotations
// say nonnull (e.g., C_Initialize(NULL), C_GetSlotList with NULL to get count).
// We suppress -Wnonnull only around those specific call sites using push/pop.

#import "PKCS11.h"

#include <dlfcn.h>
#include <fcntl.h>
#import <os/log.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>

static NSMutableDictionary<NSString *, PKCS11Module *> *gSharedModules = nil;
static dispatch_once_t gOnceToken;
// Semaphore to serialize fchdir+dlopen when the per-thread CWD API is
// unavailable.  Only used as a fallback — see __pthread_fchdir usage below.
static dispatch_semaphore_t gChdirSemaphore = NULL;

// Per-thread CWD — macOS kernel syscall available since 10.5.
// Changes the working directory for the calling thread ONLY; other threads
// (including CryptoTokenKit framework internals) never see the change.
// Pass -1 to clear the per-thread override and revert to the process CWD.
// Declared weak so we can detect availability at runtime.
extern int __pthread_fchdir(int fd) __attribute__((weak_import));

#pragma mark - Helpers

/// Compute SHA-512 hash of a file using an already-open file descriptor.
/// This avoids the TOCTOU window that exists when hashing by path then
/// separately opening via dlopen.  The fd is read from offset 0.
static NSString *_Nullable PKCS11ComputeSHA512FromFd(int fd) {
  if (fd < 0)
    return nil;

  // Seek to beginning
  if (lseek(fd, 0, SEEK_SET) != 0)
    return nil;

  CC_SHA512_CTX ctx;
  CC_SHA512_Init(&ctx);

  uint8_t buf[8192];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    CC_SHA512_Update(&ctx, buf, (CC_LONG)n);
  }
  if (n < 0)
    return nil; // read error

  unsigned char digest[CC_SHA512_DIGEST_LENGTH];
  CC_SHA512_Final(digest, &ctx);

  NSMutableString *hash =
      [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
    [hash appendFormat:@"%02x", digest[i]];
  }
  return hash;
}

static NSError *PKCS11MakeError(NSInteger code, NSString *message) {
  return
      [NSError errorWithDomain:@"com.andrei.rocei.connector.PKCS11"
                          code:code
                      userInfo:@{
                        NSLocalizedDescriptionKey : message ?: @"PKCS11 error"
                      }];
}

/// Securely clears sensitive data from memory using memset_s to prevent
/// compiler optimization from eliding the clear.
void PKCS11SecureClearData(NSMutableData *data) {
  if (data && data.length > 0) {
    memset_s(data.mutableBytes, data.length, 0, data.length);
  }
}

static NSData *_Nullable PKCS11DERUnwrapOctetString(NSData *der) {
  const uint8_t *p = der.bytes;
  NSUInteger len = der.length;
  if (len < 2 || p[0] != 0x04) {
    return nil;
  }
  uint8_t l = p[1];
  NSUInteger offset = 2;
  NSUInteger contentLen = 0;
  if ((l & 0x80) == 0) {
    contentLen = l;
  } else {
    uint8_t n = (uint8_t)(l & 0x7F);
    if (n == 0 || n > 4 || len < 2 + n)
      return nil;
    // Reject non-minimal DER: first byte of multi-byte length must not be 0x00
    // (unless encoding would still require multiple bytes after removing it)
    if (n > 1 && p[offset] == 0x00)
      return nil;
    contentLen = 0;
    for (uint8_t i = 0; i < n; i++) {
      contentLen = (contentLen << 8) | p[offset + i];
    }
    // Additional check: if n == 1 and value <= 0x7F, should have used short
    // form
    if (n == 1 && contentLen <= 0x7F)
      return nil;
    offset += n;
  }
  if (len < offset + contentLen)
    return nil;
  return [der subdataWithRange:NSMakeRange(offset, contentLen)];
}

static NSNumber *_Nullable PKCS11KeySizeBitsFromECParams(NSData *ecParams) {
  // Expect DER OID:
  // secp256r1: 06 08 2A 86 48 CE 3D 03 01 07
  // secp384r1: 06 05 2B 81 04 00 22
  const uint8_t *p = ecParams.bytes;
  NSUInteger len = ecParams.length;
  if (len >= 2 && p[0] == 0x06) {
    // Skip OID header/len, compare value bytes.
    uint8_t l = p[1];
    if (len >= 2 + l) {
      const uint8_t *oid = p + 2;
      if (l == 8 && memcmp(oid,
                           (const uint8_t[]){0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
                                             0x01, 0x07},
                           8) == 0) {
        return @(256);
      }
      if (l == 5 && memcmp(oid, (const uint8_t[]){0x2B, 0x81, 0x04, 0x00, 0x22},
                           5) == 0) {
        return @(384);
      }
    }
  }
  return nil;
}

#pragma mark - PKCS11Module

@interface PKCS11Module () {
  /// Tracks the number of threads actively using this module's PKCS#11
  /// function pointers (e.g. between beginUse / endUse pairs).  While
  /// _activeUseCount > 0, finalizeAndReset: will block and
  /// clearSharedModuleCache will skip this module.  This prevents a
  /// concurrent reset from dlclose-ing the library while another thread
  /// is mid-operation (function pointers would become dangling).
  atomic_int _activeUseCount;

  /// Set to YES when a timeout fires during C_Sign or C_Login.
  /// A timed-out PKCS#11 call continues in the background on an orphaned
  /// GCD thread; we cannot cancel it or predict when it finishes.  Any
  /// further use of the session or library (C_Logout, C_CloseSession,
  /// new C_SignInit, etc.) is undefined behaviour and may crash.
  ///
  /// Once poisoned, every operation except finalizeAndReset: immediately
  /// returns NO with a descriptive error.  finalizeAndReset: calls
  /// C_Finalize (which hard-closes all sessions inside the PKCS#11
  /// library) and then clears the flag so the module can be re-used.
  atomic_bool _poisoned;
}
@property(nonatomic, copy) NSString *bundleResourcePath;
@property(nonatomic, copy, nullable) NSString *modulePathOverride;
@property(nonatomic, copy, nullable) NSString *configDirectoryOverride;
@property(nonatomic) void *dlHandle;
@property(nonatomic) BOOL initialized;

// Direct function pointers (from dlsym, more reliable than CK_FUNCTION_LIST)
@property(nonatomic) PFN_C_Initialize fn_Initialize;
@property(nonatomic) PFN_C_Finalize fn_Finalize;
@property(nonatomic) PFN_C_GetSlotList fn_GetSlotList;
@property(nonatomic) PFN_C_GetTokenInfo fn_GetTokenInfo;
@property(nonatomic) PFN_C_GetSessionInfo fn_GetSessionInfo;
@property(nonatomic) PFN_C_OpenSession fn_OpenSession;
@property(nonatomic) PFN_C_CloseSession fn_CloseSession;
@property(nonatomic) PFN_C_Login fn_Login;
@property(nonatomic) PFN_C_Logout fn_Logout;
@property(nonatomic) PFN_C_FindObjectsInit fn_FindObjectsInit;
@property(nonatomic) PFN_C_FindObjects fn_FindObjects;
@property(nonatomic) PFN_C_FindObjectsFinal fn_FindObjectsFinal;
@property(nonatomic) PFN_C_GetAttributeValue fn_GetAttributeValue;
@property(nonatomic) PFN_C_SignInit fn_SignInit;
@property(nonatomic) PFN_C_Sign fn_Sign;
@property(nonatomic) PFN_C_GetMechanismList fn_GetMechanismList;
@property(nonatomic) PFN_C_GetMechanismInfo fn_GetMechanismInfo;
@property(nonatomic) PFN_C_DeriveKey fn_DeriveKey;
@end

@implementation PKCS11Module

#pragma mark - Shared instance management

/// Returns a shared singleton PKCS#11 module instance for the given module
/// path. This ensures only one C_Initialize call per module path, which is
/// critical because:
/// 1. Multiple C_Initialize calls can cause issues with some PKCS#11 libraries
/// (especially IDEMIA)
/// 2. The IDEMIA library has non-standard function list offsets, so direct
/// dlsym is used instead
/// 3. Shared instances reduce memory usage and initialization overhead
///
/// Thread-safety: The @synchronized block protects the cache lookup and
/// insertion.  The module's internal use-count (beginUse / endUse) prevents
/// clearSharedModuleCache or finalizeAndReset: from tearing down a module
/// that is still in use by another thread.
///
/// @param modulePath Full path to PKCS#11 library (e.g.,
/// "/Applications/IDplugManager.app/.../libidplug-pkcs11.dylib")
/// @param configDirectory Directory for PKCS#11 config files (some libraries
/// require CWD to be set)
/// @return Shared module instance, or nil if initialization fails
+ (instancetype)sharedModuleWithPath:(NSString *)modulePath
                     configDirectory:(nullable NSString *)configDirectory {
  dispatch_once(&gOnceToken, ^{
    gSharedModules = [NSMutableDictionary dictionary];
    gChdirSemaphore = dispatch_semaphore_create(1); // Serialize fchdir+dlopen
  });

  PKCS11Module *module = nil;
  @synchronized(gSharedModules) {
    // Check if module already exists for this path
    PKCS11Module *existing = gSharedModules[modulePath];
    if (existing) {
      os_log(OS_LOG_DEFAULT, "PKCS11: returning cached module for %{public}@",
             modulePath);
      module = existing;
    } else {
      // Create and initialize new module
      PKCS11Module *newModule =
          [[PKCS11Module alloc] initWithModulePath:modulePath
                                   configDirectory:configDirectory];
      NSError *error = nil;
      if ([newModule loadAndInitialize:&error]) {
        // Cache successfully initialized module
        gSharedModules[modulePath] = newModule;
        os_log(OS_LOG_DEFAULT,
               "PKCS11: created and cached new shared module for %{public}@",
               modulePath);
        module = newModule;
      } else {
        os_log_error(OS_LOG_DEFAULT,
                     "PKCS11: failed to initialize module "
                     "%{public}@: %{public}@",
                     modulePath, error);
      }
    }
  }

  return module;
}

/// Clears the shared module cache, removing only modules with no active users.
/// Modules still in use (activeUseCount > 0) are retained until all users
/// call endUse.
+ (void)clearSharedModuleCache {
  dispatch_once(&gOnceToken, ^{
    gSharedModules = [NSMutableDictionary dictionary];
  });
  @synchronized(gSharedModules) {
    // Only remove modules that have no active users.  If a module is still
    // in use (activeUseCount > 0), skip it — it will be cleaned up when the
    // last user calls endUse and a subsequent clearSharedModuleCache fires.
    NSMutableArray<NSString *> *keysToRemove = [NSMutableArray array];
    for (NSString *key in gSharedModules) {
      PKCS11Module *m = gSharedModules[key];
      if (atomic_load(&m->_activeUseCount) == 0) {
        [keysToRemove addObject:key];
      } else {
        os_log(OS_LOG_DEFAULT,
               "PKCS11: clearSharedModuleCache: skipping in-use module "
               "%{public}@ (activeUseCount=%d)",
               key, atomic_load(&m->_activeUseCount));
      }
    }
    os_log(OS_LOG_DEFAULT,
           "PKCS11: clearing shared module cache (%lu of %lu entries)",
           (unsigned long)keysToRemove.count,
           (unsigned long)gSharedModules.count);
    [gSharedModules removeObjectsForKeys:keysToRemove];
  }
}

#pragma mark - Initializers

/// Initializes a module that discovers the PKCS#11 library inside the
/// appex bundle's Resources directory.
///
/// @param bundleResourcePath Path to the bundle's resourcePath
- (instancetype)initWithBundleResourcePath:(NSString *)bundleResourcePath {
  self = [super init];
  if (self) {
    _bundleResourcePath = [bundleResourcePath copy];
    _modulePathOverride = nil;
    _configDirectoryOverride = nil;
    _dlHandle = NULL;
    _initialized = NO;
  }
  return self;
}

/// Initializes a module with an explicit PKCS#11 library path and an
/// optional config directory (some libraries need CWD set).
///
/// @param modulePath Full path to .dylib
/// @param configDirectory Optional directory to chdir into before dlopen
- (instancetype)initWithModulePath:(NSString *)modulePath
                   configDirectory:(nullable NSString *)configDirectory {
  self = [super init];
  if (self) {
    _bundleResourcePath = @"";
    _modulePathOverride = [modulePath copy];
    _configDirectoryOverride = [configDirectory copy];
    _dlHandle = NULL;
    _initialized = NO;
  }
  return self;
}

/// Returns the resolved path to the PKCS#11 .dylib.
/// Prefers modulePathOverride if set; otherwise appends the library filename
/// to bundleResourcePath.
- (NSString *)modulePath {
  if (self.modulePathOverride.length > 0) {
    return self.modulePathOverride;
  }
  return [self.bundleResourcePath
      stringByAppendingPathComponent:@"libidplug-pkcs11.dylib"];
}

#pragma mark - Use-count (thread-safety for shared modules)

/// Increments the atomic use-count. Prevents clearSharedModuleCache from
/// removing this module while an operation is in flight.
- (void)beginUse {
  int prev = atomic_fetch_add(&_activeUseCount, 1);
  os_log_debug(OS_LOG_DEFAULT, "PKCS11: beginUse (activeUseCount %d → %d)",
               prev, prev + 1);
}

/// Decrements the atomic use-count. Logs an error on underflow.
- (void)endUse {
  int prev = atomic_fetch_sub(&_activeUseCount, 1);
  if (prev <= 0) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: endUse called with activeUseCount=%d (underflow!)",
                 prev);
  } else {
    os_log_debug(OS_LOG_DEFAULT, "PKCS11: endUse (activeUseCount %d → %d)",
                 prev, prev - 1);
  }
}

/// Returns the current atomic use-count.
- (int)activeUseCount {
  return atomic_load(&_activeUseCount);
}

/// Returns YES if the module has been poisoned after a timeout.
- (BOOL)isPoisoned {
  return atomic_load(&_poisoned);
}

/// Marks the module as poisoned.  Called when a timeout fires while a PKCS#11
/// call is still running in the background.  All subsequent operations (except
/// finalizeAndReset:) will immediately fail.
- (void)markPoisoned {
  atomic_store(&_poisoned, true);
  os_log_error(OS_LOG_DEFAULT,
               "PKCS11: *** MODULE POISONED *** — a PKCS#11 call timed out "
               "and is still running in the background.  All further "
               "operations will be refused until finalizeAndReset: is called.");
}

/// Returns YES if the module is ready for use.  Returns NO and populates
/// *error if the module is poisoned.
- (BOOL)requireNotPoisoned:(NSError *_Nullable *_Nullable)error {
  if (atomic_load(&_poisoned)) {
    if (error) {
      *error = PKCS11MakeError(
          -99, @"PKCS#11 module is poisoned after a timeout.  A previous "
               @"smart card operation timed out and may still be running "
               @"in the background.  Replug the card reader and retry.");
    }
    return NO;
  }
  return YES;
}

#pragma mark - Load & Initialize

/// Loads the PKCS#11 library and initializes it.
/// This method:
/// 1. Verifies the library's SHA-512 hash (supply-chain defence)
/// 2. Serializes fchdir+dlopen via semaphore (thread safety - minimizes CWD
/// change window)
/// 3. Sets the current working directory (some libraries require config files
/// relative to CWD)
/// 4. Dynamically loads the PKCS#11 library via dlopen
/// 5. Resolves function pointers via dlsym (more reliable than CK_FUNCTION_LIST
/// for IDEMIA library)
/// 6. Calls C_Initialize to initialize the PKCS#11 library
///
/// Note: We use dlsym instead of C_GetFunctionList because the IDEMIA library
/// has non-standard function list structure offsets that don't match the
/// PKCS#11 spec.
///
/// @param error Optional error output
/// @return YES if initialization succeeded, NO otherwise
- (BOOL)loadAndInitialize:(NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  if (self.initialized) {
    return YES; // Already initialized
  }

  NSString *path = [self modulePath];

  // ── Determine whether the library lives inside our own app bundle ─────
  // Libraries bundled inside the .app (or .appex) are protected by macOS
  // code signing — the OS validates the signature at load time.  The build
  // script also re-signs copied dylibs with our identity, which changes
  // their SHA-512 hash.  So we only enforce our own hash verification for
  // libraries loaded from *external* locations (IDplugManager install dir,
  // Application Support cache, etc.) where macOS code signing does not
  // cover them.
  NSString *mainBundlePath = [NSBundle mainBundle].bundlePath;
  BOOL isInsideOwnBundle =
      (mainBundlePath.length > 0 &&
       [path hasPrefix:[mainBundlePath stringByAppendingString:@"/"]]);

  // ── SECURITY: Verify library hash before loading ──────────────────────
  // TOCTOU mitigation: open the file once via fd, hash from the fd, then
  // after dlopen verify the loaded file is the same inode we hashed.
  int hashFd = open(path.fileSystemRepresentation, O_RDONLY);
  if (hashFd < 0) {
    if (error) {
      *error = PKCS11MakeError(
          -1,
          [NSString stringWithFormat:@"Failed to open %@ for hash verification",
                                     path]);
    }
    return NO;
  }

  // Record the inode of the file we're about to hash
  struct stat hashStat;
  if (fstat(hashFd, &hashStat) != 0) {
    close(hashFd);
    if (error) {
      *error = PKCS11MakeError(-1, @"fstat failed during hash verification");
    }
    return NO;
  }

  if (isInsideOwnBundle) {
    // Library is inside our own code-signed bundle — macOS validates its
    // integrity via the app's code signature.  Skip SHA-512 verification
    // because the build process re-signs the dylib, changing its hash.
    close(hashFd);
    os_log(OS_LOG_DEFAULT,
           "PKCS11: Library is inside own bundle (%{public}@) — "
           "skipping SHA-512 hash verification (covered by code signing)",
           path);
  } else {
    // External library — verify SHA-512 hash (supply-chain gate)
    NSString *actualHash = PKCS11ComputeSHA512FromFd(hashFd);
    close(hashFd);

    if (!actualHash) {
      if (error) {
        *error = PKCS11MakeError(
            -1,
            [NSString stringWithFormat:@"Failed to compute hash for %@", path]);
      }
      return NO;
    }

    NSArray<NSString *> *knownHashes = PKCS11KnownGoodLibraryHashes();
    if (![knownHashes containsObject:actualHash]) {
      os_log_error(OS_LOG_DEFAULT,
                   "PKCS11: Library hash mismatch! Expected one of %{public}@, "
                   "got %{public}@",
                   knownHashes, actualHash);
      if (error) {
        NSString *expectedHashList =
            [knownHashes componentsJoinedByString:@"\n  "];
        *error = PKCS11MakeError(
            -1,
            [NSString stringWithFormat:
                          @"PKCS#11 library hash verification "
                          @"failed.\n\nExpected (known-good IDplugManager "
                          @"versions):\n  %@\n\nActual:\n  %@\n\n"
                          @"This usually indicates an incompatible "
                          @"IDplugManager version. "
                          @"Please ensure you have installed a supported "
                          @"version of IDplugManager (4.5.0 or compatible).",
                          expectedHashList, actualHash]);
      }
      return NO;
    }
    os_log(OS_LOG_DEFAULT, "PKCS11: Library hash verified: %{public}@",
           actualHash);
  }

  // ── CWD change for dlopen ──────────────────────────────────────────────
  // IDEMIA's libidplug-pkcs11.dylib requires config files in CWD at dlopen
  // time.  We try two strategies, in order of preference:
  //
  //   1. __pthread_fchdir() — per-thread CWD (stable macOS kernel syscall,
  //      available since 10.5).  Only the calling thread sees the changed
  //      directory; other threads (including CryptoTokenKit internals) are
  //      unaffected.  No serialization required.
  //
  //   2. fchdir() — process-wide CWD (fallback).  Serialized with
  //      gChdirSemaphore to prevent concurrent CWD mutations.  Other
  //      threads *may* momentarily observe the changed directory.
  //
  // In both cases we restore the original CWD immediately after dlopen.
  //
  // TOCTOU: After dlopen, we stat the path and verify the inode matches
  // hashStat to detect file replacement between hash verification and load.

  // Determine target directory for CWD change
  const char *targetPath = NULL;
  if (self.configDirectoryOverride.length > 0) {
    targetPath = self.configDirectoryOverride.fileSystemRepresentation;
  } else if (self.bundleResourcePath.length > 0) {
    targetPath = self.bundleResourcePath.fileSystemRepresentation;
  }

  int targetDirFd = -1;
  int originalCwdFd = -1;
  BOOL usedPerThreadCwd = NO;
  BOOL acquiredSemaphore = NO;

  if (targetPath) {
    targetDirFd = open(targetPath, O_RDONLY | O_DIRECTORY);
    if (targetDirFd < 0) {
      os_log_error(OS_LOG_DEFAULT,
                   "PKCS11: Failed to open config directory %{public}s "
                   "(errno=%d): %{public}s",
                   targetPath, errno, strerror(errno));
    }
  }

  if (targetDirFd >= 0) {
    // Strategy 1: per-thread CWD (preferred — no process-wide side effects)
    if (__pthread_fchdir != NULL && __pthread_fchdir(targetDirFd) == 0) {
      usedPerThreadCwd = YES;
      os_log(OS_LOG_DEFAULT,
             "PKCS11: Set per-thread CWD to %{public}s for dlopen "
             "(thread-local, no process-wide impact)",
             targetPath);
    } else {
      // Strategy 2: process-wide fchdir (serialized with semaphore)
      if (__pthread_fchdir != NULL) {
        os_log(OS_LOG_DEFAULT,
               "PKCS11: __pthread_fchdir failed (errno=%d), "
               "falling back to process-wide fchdir",
               errno);
      }
      dispatch_semaphore_wait(gChdirSemaphore, DISPATCH_TIME_FOREVER);
      acquiredSemaphore = YES;

      originalCwdFd = open(".", O_RDONLY | O_DIRECTORY);
      if (originalCwdFd < 0) {
        os_log_error(OS_LOG_DEFAULT,
                     "PKCS11: Failed to open current directory (errno=%d): "
                     "%{public}s",
                     errno, strerror(errno));
      }
      if (fchdir(targetDirFd) != 0) {
        os_log_error(OS_LOG_DEFAULT,
                     "PKCS11: fchdir to %{public}s failed (errno=%d): "
                     "%{public}s",
                     targetPath, errno, strerror(errno));
      } else {
        os_log(OS_LOG_DEFAULT,
               "PKCS11: Temporarily changed process CWD to %{public}s "
               "for dlopen (serialized)",
               targetPath);
      }
    }
    close(targetDirFd);
    targetDirFd = -1;
  }

  // Dynamically load the PKCS#11 library
  self.dlHandle = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
  // RTLD_NOW: resolve all symbols immediately
  // RTLD_LOCAL: symbols are not available to other loaded libraries

  // THREAD-SAFETY: Capture dlerror() immediately before restoring CWD.
  // dlerror() is not thread-safe and its return value can be overwritten by
  // other threads.
  const char *dlerr = self.dlHandle ? NULL : dlerror();
  NSString *dlerrMsg = dlerr ? [NSString stringWithUTF8String:dlerr] : nil;

  // ── Restore CWD ───────────────────────────────────────────────────────
  if (usedPerThreadCwd) {
    // Clear per-thread CWD override; this thread reverts to process CWD.
    __pthread_fchdir(-1);
  } else if (originalCwdFd >= 0) {
    if (fchdir(originalCwdFd) != 0) {
      os_log_error(OS_LOG_DEFAULT,
                   "PKCS11: Failed to restore original CWD (errno=%d): "
                   "%{public}s",
                   errno, strerror(errno));
    }
    close(originalCwdFd);
    originalCwdFd = -1;
  }
  if (acquiredSemaphore) {
    dispatch_semaphore_signal(gChdirSemaphore);
  }

  if (!self.dlHandle) {
    if (error) {
      *error = PKCS11MakeError(
          -1, [NSString stringWithFormat:@"dlopen failed for %@: %@", path,
                                         dlerrMsg ?: @"(unknown error)"]);
    }
    return NO;
  }

  // ── TOCTOU verification: ensure dlopen loaded the same file we hashed ─
  struct stat postStat;
  if (stat(path.fileSystemRepresentation, &postStat) != 0 ||
      postStat.st_dev != hashStat.st_dev ||
      postStat.st_ino != hashStat.st_ino) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: TOCTOU DETECTED — library inode changed between "
                 "hash verification and dlopen!  Unloading.");
    dlclose(self.dlHandle);
    self.dlHandle = NULL;
    if (error) {
      *error = PKCS11MakeError(
          -1, @"PKCS#11 library file was replaced between hash verification "
              @"and loading.  This may indicate tampering.");
    }
    return NO;
  }
  os_log(OS_LOG_DEFAULT, "PKCS11: module loaded: %{public}@", path);

  // ── Load function pointers directly via dlsym ─────────────────────────
  // This is more reliable than using C_GetFunctionList because:
  // 1. The IDEMIA library has non-standard function list structure offsets
  // 2. Direct dlsym avoids potential ABI compatibility issues
  // 3. We only need a subset of PKCS#11 functions, so direct resolution is
  // simpler
  self.fn_Initialize = (PFN_C_Initialize)dlsym(self.dlHandle, "C_Initialize");
  self.fn_Finalize = (PFN_C_Finalize)dlsym(self.dlHandle, "C_Finalize");
  self.fn_GetSlotList =
      (PFN_C_GetSlotList)dlsym(self.dlHandle, "C_GetSlotList");
  self.fn_GetTokenInfo =
      (PFN_C_GetTokenInfo)dlsym(self.dlHandle, "C_GetTokenInfo");
  self.fn_GetSessionInfo =
      (PFN_C_GetSessionInfo)dlsym(self.dlHandle, "C_GetSessionInfo");
  self.fn_OpenSession =
      (PFN_C_OpenSession)dlsym(self.dlHandle, "C_OpenSession");
  self.fn_CloseSession =
      (PFN_C_CloseSession)dlsym(self.dlHandle, "C_CloseSession");
  self.fn_Login = (PFN_C_Login)dlsym(self.dlHandle, "C_Login");
  self.fn_Logout = (PFN_C_Logout)dlsym(self.dlHandle, "C_Logout");
  self.fn_FindObjectsInit =
      (PFN_C_FindObjectsInit)dlsym(self.dlHandle, "C_FindObjectsInit");
  self.fn_FindObjects =
      (PFN_C_FindObjects)dlsym(self.dlHandle, "C_FindObjects");
  self.fn_FindObjectsFinal =
      (PFN_C_FindObjectsFinal)dlsym(self.dlHandle, "C_FindObjectsFinal");
  self.fn_GetAttributeValue =
      (PFN_C_GetAttributeValue)dlsym(self.dlHandle, "C_GetAttributeValue");
  self.fn_SignInit = (PFN_C_SignInit)dlsym(self.dlHandle, "C_SignInit");
  self.fn_Sign = (PFN_C_Sign)dlsym(self.dlHandle, "C_Sign");
  self.fn_GetMechanismList =
      (PFN_C_GetMechanismList)dlsym(self.dlHandle, "C_GetMechanismList");
  self.fn_GetMechanismInfo =
      (PFN_C_GetMechanismInfo)dlsym(self.dlHandle, "C_GetMechanismInfo");
  self.fn_DeriveKey = (PFN_C_DeriveKey)dlsym(self.dlHandle, "C_DeriveKey");

  // Verify critical functions were found
  if (!self.fn_Initialize || !self.fn_GetSlotList || !self.fn_OpenSession ||
      !self.fn_FindObjectsInit || !self.fn_FindObjects ||
      !self.fn_FindObjectsFinal || !self.fn_GetAttributeValue ||
      !self.fn_SignInit || !self.fn_Sign || !self.fn_Login ||
      !self.fn_CloseSession) {
    if (error) {
      *error = PKCS11MakeError(
          -2, @"Failed to find required PKCS#11 functions via dlsym");
    }
    return NO;
  }
  os_log(OS_LOG_DEFAULT, "PKCS11: functions loaded via dlsym");

  // ── Initialize PKCS#11 library ────────────────────────────────────────
  os_log(OS_LOG_DEFAULT, "PKCS11: calling C_Initialize...");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  CK_RV rv = self.fn_Initialize(NULL);
#pragma clang diagnostic pop
  os_log(OS_LOG_DEFAULT, "PKCS11: C_Initialize returned: 0x%08lx",
         (unsigned long)rv);
  // CKR_CRYPTOKI_ALREADY_INITIALIZED is OK (library was already initialized
  // elsewhere)
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_Initialize failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return NO;
  }

  // Get slot count for debugging (tokenPresent=1 means only slots with tokens)
  CK_ULONG slotCount = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  rv = self.fn_GetSlotList(1, NULL, &slotCount);
#pragma clang diagnostic pop
  os_log(OS_LOG_DEFAULT, "PKCS11: C_GetSlotList returned: 0x%08lx, count=%lu",
         (unsigned long)rv, (unsigned long)slotCount);

  self.initialized = YES;
  os_log(OS_LOG_DEFAULT, "PKCS11: initialized (module=%{public}@)", path);
  return YES;
}

#pragma mark - Finalize

/// Finalizes the PKCS#11 library and releases all resources.
/// Waits for active users to complete (up to 10 seconds) before calling
/// C_Finalize. Clears the poisoned flag and removes from shared cache.
/// Safe to call even if library is not initialized.
///
/// @param error Optional error output
/// @return YES if finalize succeeded, NO otherwise
- (BOOL)finalizeAndReset:(NSError *_Nullable *_Nullable)error {
  if (!self.initialized || !self.dlHandle) {
    os_log(OS_LOG_DEFAULT,
           "PKCS11: finalizeAndReset: not initialized, nothing to do");
    return YES;
  }

  // Wait for any in-flight operations to finish before tearing down.
  // Use a bounded spin-wait (up to 10 s) to avoid dlclose while another
  // thread is using the function pointers.
  static const int kMaxWaitMs = 10000;
  static const int kPollIntervalMs = 50;
  int waited = 0;
  while (atomic_load(&_activeUseCount) > 0 && waited < kMaxWaitMs) {
    os_log(OS_LOG_DEFAULT,
           "PKCS11: finalizeAndReset: waiting for %d active user(s) to "
           "finish...",
           atomic_load(&_activeUseCount));
    usleep((useconds_t)(kPollIntervalMs * 1000));
    waited += kPollIntervalMs;
  }
  if (atomic_load(&_activeUseCount) > 0) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: finalizeAndReset: timed out waiting for %d active "
                 "user(s); proceeding with finalize (risk of crash)",
                 atomic_load(&_activeUseCount));
  }

  CK_RV rv = CKR_OK;
  if (self.fn_Finalize) {
    os_log(OS_LOG_DEFAULT, "PKCS11: calling C_Finalize...");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
    rv = self.fn_Finalize(NULL);
#pragma clang diagnostic pop
    os_log(OS_LOG_DEFAULT, "PKCS11: C_Finalize returned: 0x%08lx",
           (unsigned long)rv);
  }

  self.initialized = NO;

  // Clear poisoned flag — C_Finalize has hard-closed all sessions inside the
  // library, so the orphaned background block (if any) will return a stale
  // error the next time the GCD thread wakes, but it can no longer corrupt
  // any shared state.  The module is now safe to re-initialize.
  atomic_store(&_poisoned, false);
  os_log(OS_LOG_DEFAULT,
         "PKCS11: finalizeAndReset: poisoned flag cleared, module may be "
         "re-initialized");

  // Remove from shared module cache
  [PKCS11Module clearSharedModuleCache];

  if (rv != CKR_OK && rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_Finalize failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return NO;
  }
  return YES;
}

#pragma mark - Slot / Session

/// Finds the first PKCS#11 slot that has a token present.
/// This is used for auto-detection when the user hasn't specified a slot.
///
/// @param error Optional error output
/// @return Slot ID as NSNumber, or nil if no token is present or on error
- (nullable NSNumber *)firstTokenSlot:
    (NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self loadAndInitialize:error]) {
    return nil;
  }

  CK_ULONG count = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  CK_RV rv = self.fn_GetSlotList((CK_BBOOL)1, NULL, &count);
#pragma clang diagnostic pop
  if (rv != CKR_OK) {
    if (error) {
      *error = PKCS11MakeError(
          rv,
          [NSString stringWithFormat:@"C_GetSlotList(count) failed: 0x%08lx",
                                     (unsigned long)rv]);
    }
    return nil;
  }
  if (count == 0) {
    if (error) {
      *error =
          PKCS11MakeError(CKR_TOKEN_NOT_PRESENT, @"No PKCS#11 token present");
    }
    return nil;
  }

  // Dynamically allocate slot array to handle any number of slots
  CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc(count, sizeof(CK_SLOT_ID));
  if (!slots) {
    if (error) {
      *error = PKCS11MakeError(-1, @"Failed to allocate memory for slot list");
    }
    return nil;
  }

  rv = self.fn_GetSlotList((CK_BBOOL)1, slots, &count);
  if (rv != CKR_OK || count == 0) {
    free(slots);
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_GetSlotList(list) failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return nil;
  }

  // Log all available slots for debugging
  for (CK_ULONG i = 0; i < count; i++) {
    os_log(OS_LOG_DEFAULT, "PKCS11: C_GetSlotList: slot[%lu] = 0x%lx (%lu)",
           (unsigned long)i, (unsigned long)slots[i], (unsigned long)slots[i]);
  }
  CK_SLOT_ID firstSlot = slots[0];
  free(slots);

  os_log(OS_LOG_DEFAULT, "PKCS11: firstTokenSlot returning: 0x%lx (%lu)",
         (unsigned long)firstSlot, (unsigned long)firstSlot);
  return @(firstSlot);
}

/// Opens a PKCS#11 session on the specified slot.
/// Sessions are used for all PKCS#11 operations (login, find objects, sign,
/// etc.). This opens a serial session (CKF_SERIAL_SESSION) which is required
/// for most operations.
///
/// @param slot PKCS#11 slot ID (e.g., 0x1 for authentication slot, 0x2 for
/// signing slot)
/// @param outSession Output parameter for the session handle
/// @param error Optional error output
/// @return YES if session opened successfully, NO otherwise
- (BOOL)openSessionOnSlot:(uint32_t)slot
                  session:(CK_SESSION_HANDLE *)outSession
                    error:(NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self loadAndInitialize:error]) {
    return NO;
  }

  os_log(OS_LOG_DEFAULT,
         "PKCS11: openSessionOnSlot: attempting slot=0x%lx (%lu)",
         (unsigned long)slot, (unsigned long)slot);
  CK_SESSION_HANDLE session = 0;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  CK_RV rv = self.fn_OpenSession((CK_SLOT_ID)slot, flags, NULL, NULL, &session);
#pragma clang diagnostic pop
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: C_OpenSession FAILED: slot=0x%lx "
                 "flags=0x%lx rv=0x%lx",
                 (unsigned long)slot, (unsigned long)flags, (unsigned long)rv);
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_OpenSession failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return NO;
  }
  os_log(OS_LOG_DEFAULT,
         "PKCS11: C_OpenSession SUCCESS: slot=0x%lx session=0x%lx "
         "flags=0x%lx",
         (unsigned long)slot, (unsigned long)session, (unsigned long)flags);
  *outSession = session;
  return YES;
}

/// Closes a PKCS#11 session, releasing its resources.
/// This should be called after operations are complete to prevent session
/// exhaustion.
///
/// @param session PKCS#11 session handle to close
/// @param error Optional error output
/// @return YES if close succeeded, NO otherwise
- (BOOL)closeSession:(CK_SESSION_HANDLE)session
               error:(NSError *_Nullable *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  if (!self.dlHandle || !self.fn_CloseSession) {
    if (error) {
      *error = PKCS11MakeError(-1, @"Module not loaded");
    }
    return NO;
  }

  CK_RV rv = self.fn_CloseSession(session);
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: C_CloseSession FAILED: session=0x%lx rv=0x%lx",
                 (unsigned long)session, (unsigned long)rv);
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_CloseSession failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return NO;
  }

  os_log(OS_LOG_DEFAULT, "PKCS11: C_CloseSession OK: session=0x%lx",
         (unsigned long)session);
  return YES;
}

#pragma mark - Login / Logout

/// Authenticates the user on a PKCS#11 session using the provided PIN.
/// This must be called before accessing private keys or performing signing
/// operations. The PIN is provided as NSData (UTF-8 encoded bytes) for secure
/// handling.
///
/// Protected by a 30-second timeout; returns an error if the smart card reader
/// hangs.  Provides detailed messages for PIN_INCORRECT (with final-try
/// warning via CK_TOKEN_INFO) and PIN_LOCKED.
///
/// The caller is responsible for clearing pinData after use (see
/// PKCS11SecureClearData()).
///
/// @param session PKCS#11 session handle (must be opened first)
/// @param pinData User PIN as NSMutableData (UTF-8 encoded, 4 digits for auth
///                slot, 6 digits for signing slots).
/// @param error Optional error output
/// @return YES if login succeeded, NO otherwise
- (BOOL)loginUserOnSession:(CK_SESSION_HANDLE)session
                   pinData:(NSMutableData *)pinData
                     error:
                         (NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self loadAndInitialize:error]) {
    return NO;
  }

  // Wrap C_Login with timeout to prevent indefinite hangs (e.g., USB reader
  // issues). If the smart card reader hangs, we return an error after 30 s.
  //
  // Defensive copy: the caller clears pinData with PKCS11SecureClearData()
  // after this method returns.  If the timeout fires first, the background
  // block would read zeroed/freed memory — a use-after-free risk.  We give
  // the block its own copy and securely clear it once C_Login returns.
  __block CK_RV rv = CKR_GENERAL_ERROR;
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  NSMutableData *pinCopy = [NSMutableData dataWithData:pinData];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    rv = self.fn_Login(session, CKU_USER, (CK_BYTE_PTR)pinCopy.bytes,
                       (CK_ULONG)pinCopy.length);
    PKCS11SecureClearData(pinCopy);
    dispatch_semaphore_signal(sem);
  });

  // Wait up to 30 seconds for C_Login to complete
  long timeout = dispatch_semaphore_wait(
      sem, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));

  if (timeout != 0) {
    os_log_error(OS_LOG_DEFAULT, "PKCS11: C_Login TIMED OUT after 30 seconds");

    // SECURITY: The background C_Login is still running on an orphaned GCD
    // thread.  We cannot safely call C_Logout or C_CloseSession because:
    // 1. We don't know when the background C_Login will complete
    // 2. If it eventually succeeds, the session will be logged in without
    //    explicit PIN verification
    // 3. Calling logout/close now would race against the background thread
    //
    // Solution: Mark the module as poisoned.  This prevents ALL subsequent
    // operations (including logout/close) until finalizeAndReset: is called,
    // which hard-closes every session inside the PKCS#11 library via
    // C_Finalize, guaranteeing cleanup regardless of background thread state.
    [self markPoisoned];
    if (error) {
      *error = PKCS11MakeError(-1, @"Smart card operation timed out. The "
                                   @"module has been poisoned — replug the "
                                   @"reader and retry.");
    }
    return NO;
  }

  os_log(OS_LOG_DEFAULT, "PKCS11: C_Login returned: 0x%08lx",
         (unsigned long)rv);

  // CKR_USER_ALREADY_LOGGED_IN (0x100) is OK — session already authenticated
  if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
    return YES;
  }

  // ── Handle PIN-specific errors with detailed messages ─────────────────

  if (rv == CKR_PIN_LOCKED) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: PIN is LOCKED. Card must be reset at government "
                 "office.");
    if (error) {
      *error = PKCS11MakeError(rv, @"PIN is permanently locked. Visit a "
                                   @"government office to reset your card.");
    }
    return NO;
  }

  if (rv == CKR_PIN_INCORRECT) {
    // Try to get token info to check for final attempt warning
    CK_SESSION_INFO sessionInfo;

    if (self.fn_GetSessionInfo &&
        self.fn_GetSessionInfo(session, &sessionInfo) == CKR_OK) {
      CK_SLOT_ID slotID = sessionInfo.slotID;
      CK_TOKEN_INFO tokenInfo;

      if (self.fn_GetTokenInfo &&
          self.fn_GetTokenInfo(slotID, &tokenInfo) == CKR_OK) {
        if (tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) {
          os_log_error(OS_LOG_DEFAULT,
                       "PKCS11: PIN incorrect. WARNING: This is your FINAL "
                       "attempt!");
          if (error) {
            *error =
                PKCS11MakeError(rv, @"Incorrect PIN. ⚠️ WARNING: One attempt "
                                    @"remaining before permanent lockout!");
          }
          return NO;
        }
      }
    }

    os_log_error(OS_LOG_DEFAULT, "PKCS11: PIN incorrect.");
    if (error) {
      *error = PKCS11MakeError(rv, @"Incorrect PIN. Please try again.");
    }
    return NO;
  }

  // Generic error
  if (error) {
    *error = PKCS11MakeError(
        rv, [NSString stringWithFormat:@"C_Login failed: 0x%08lx",
                                       (unsigned long)rv]);
  }
  return NO;
}

/// Logs out from a PKCS#11 session, clearing authentication state.
/// Per PKCS#11 spec, this should be called before C_CloseSession to properly
/// clean up.
///
/// @param session PKCS#11 session handle
/// @param error Optional error output
/// @return YES if logout succeeded or user was not logged in, NO on error
- (BOOL)logoutSession:(CK_SESSION_HANDLE)session
                error:(NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  if (!self.fn_Logout) {
    // Logout function not available, treat as success (library may not support
    // it)
    return YES;
  }

  CK_RV rv = self.fn_Logout(session);
  os_log(OS_LOG_DEFAULT, "PKCS11: C_Logout returned: 0x%08lx",
         (unsigned long)rv);

  // CKR_USER_NOT_LOGGED_IN is OK — means session was already logged out
  if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: C_Logout FAILED: session=0x%lx rv=0x%lx",
                 (unsigned long)session, (unsigned long)rv);
    if (error) {
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_Logout failed: 0x%08lx",
                                         (unsigned long)rv]);
    }
    return NO;
  }

  return YES;
}

#pragma mark - Certificate / Key lookup

/// Reads a DER-encoded X.509 certificate from the token.
/// Searches for certificate objects whose CKA_LABEL contains the given
/// substring and returns the first match's CKA_VALUE.
///
/// @param labelSubstring Substring to match against CKA_LABEL
/// @param session Open PKCS#11 session handle
/// @param error Optional error output
/// @return DER-encoded certificate data, or nil if not found
- (nullable NSData *)
    readCertificateDERWithLabelSubstring:(NSString *)labelSubstring
                                 session:(CK_SESSION_HANDLE)session
                                   error:(NSError *__autoreleasing _Nullable
                                              *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return nil;
  }
  CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
  CK_ATTRIBUTE templateAttrs[1];
  templateAttrs[0].type = CKA_CLASS;
  templateAttrs[0].pValue = &cls;
  templateAttrs[0].ulValueLen = sizeof(cls);

  CK_RV rv = self.fn_FindObjectsInit(session, templateAttrs, 1);
  if (rv != CKR_OK) {
    if (error)
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_FindObjectsInit failed: 0x%08lx",
                                         (unsigned long)rv]);
    return nil;
  }

  NSData *result = nil;
  while (1) {
    CK_OBJECT_HANDLE obj = 0;
    CK_ULONG found = 0;
    rv = self.fn_FindObjects(session, &obj, 1, &found);
    if (rv != CKR_OK) {
      if (error)
        *error = PKCS11MakeError(
            rv, [NSString stringWithFormat:@"C_FindObjects failed: 0x%08lx",
                                           (unsigned long)rv]);
      break;
    }
    if (found == 0) {
      break;
    }

    // Read label first
    CK_ATTRIBUTE attrLabel;
    attrLabel.type = CKA_LABEL;
    attrLabel.pValue = NULL;
    attrLabel.ulValueLen = 0;
    rv = self.fn_GetAttributeValue(session, obj, &attrLabel, 1);
    if (rv != CKR_OK || attrLabel.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
      continue;
    }
    NSMutableData *labelBuf =
        [NSMutableData dataWithLength:attrLabel.ulValueLen];
    attrLabel.pValue = labelBuf.mutableBytes;
    rv = self.fn_GetAttributeValue(session, obj, &attrLabel, 1);
    if (rv != CKR_OK) {
      continue;
    }
    labelBuf.length = attrLabel.ulValueLen; // Update to actual returned size
    NSString *label = [[NSString alloc] initWithData:labelBuf
                                            encoding:NSUTF8StringEncoding];
    if (!label || [label rangeOfString:labelSubstring].location == NSNotFound) {
      continue;
    }

    // Read CKA_VALUE (DER)
    CK_ATTRIBUTE attrValue;
    attrValue.type = CKA_VALUE;
    attrValue.pValue = NULL;
    attrValue.ulValueLen = 0;
    rv = self.fn_GetAttributeValue(session, obj, &attrValue, 1);
    if (rv != CKR_OK || attrValue.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
      continue;
    }
    NSMutableData *valueBuf =
        [NSMutableData dataWithLength:attrValue.ulValueLen];
    attrValue.pValue = valueBuf.mutableBytes;
    rv = self.fn_GetAttributeValue(session, obj, &attrValue, 1);
    if (rv == CKR_OK) {
      valueBuf.length = attrValue.ulValueLen; // Update to actual returned size
      result = [valueBuf copy];
      break;
    }
  }

  (void)self.fn_FindObjectsFinal(session);
  if (!result && error) {
    *error = PKCS11MakeError(
        -3, [NSString
                stringWithFormat:@"No certificate matched label substring '%@'",
                                 labelSubstring]);
  }
  return result;
}

/// Finds a public EC key whose CKA_LABEL contains the given substring.
/// Extracts CKA_ID, CKA_EC_POINT (unwrapped from DER OCTET STRING), and
/// key size from CKA_EC_PARAMS.
///
/// @param labelSubstring Substring to match against key label
/// @param session Open PKCS#11 session handle
/// @param outKeyId On return, the key's CKA_ID
/// @param outEcPoint On return, the raw EC public key point
/// @param outKeySizeBits On return, key size (256 or 384)
/// @param error Optional error output
/// @return YES if a matching key was found
- (BOOL)findPublicECKeyWithLabelSubstring:(NSString *)labelSubstring
                                  session:(CK_SESSION_HANDLE)session
                                 keyIdOut:(NSData *_Nullable *_Nullable)outKeyId
                               ecPointOut:
                                   (NSData *_Nullable *_Nullable)outEcPoint
                           keySizeBitsOut:
                               (NSNumber *_Nullable *_Nullable)outKeySizeBits
                                    error:(NSError *__autoreleasing _Nullable
                                               *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE templateAttrs[1];
  templateAttrs[0].type = CKA_CLASS;
  templateAttrs[0].pValue = &cls;
  templateAttrs[0].ulValueLen = sizeof(cls);

  CK_RV rv = self.fn_FindObjectsInit(session, templateAttrs, 1);
  if (rv != CKR_OK) {
    if (error)
      *error = PKCS11MakeError(
          rv, [NSString
                  stringWithFormat:@"C_FindObjectsInit(pubkey) failed: 0x%08lx",
                                   (unsigned long)rv]);
    return NO;
  }

  BOOL ok = NO;
  while (1) {
    CK_OBJECT_HANDLE obj = 0;
    CK_ULONG found = 0;
    rv = self.fn_FindObjects(session, &obj, 1, &found);
    if (rv != CKR_OK || found == 0) {
      break;
    }

    // Label
    CK_ATTRIBUTE attrLabel = {CKA_LABEL, NULL, 0};
    rv = self.fn_GetAttributeValue(session, obj, &attrLabel, 1);
    if (rv != CKR_OK || attrLabel.ulValueLen == CK_UNAVAILABLE_INFORMATION)
      continue;
    NSMutableData *labelBuf =
        [NSMutableData dataWithLength:attrLabel.ulValueLen];
    attrLabel.pValue = labelBuf.mutableBytes;
    rv = self.fn_GetAttributeValue(session, obj, &attrLabel, 1);
    if (rv != CKR_OK)
      continue;
    labelBuf.length = attrLabel.ulValueLen; // Update to actual returned size
    NSString *label = [[NSString alloc] initWithData:labelBuf
                                            encoding:NSUTF8StringEncoding];
    if (!label || [label rangeOfString:labelSubstring].location == NSNotFound)
      continue;

    // CKA_ID
    CK_ATTRIBUTE attrId = {CKA_ID, NULL, 0};
    rv = self.fn_GetAttributeValue(session, obj, &attrId, 1);
    if (rv != CKR_OK || attrId.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        attrId.ulValueLen == 0)
      continue;
    NSMutableData *idBuf = [NSMutableData dataWithLength:attrId.ulValueLen];
    attrId.pValue = idBuf.mutableBytes;
    rv = self.fn_GetAttributeValue(session, obj, &attrId, 1);
    if (rv != CKR_OK)
      continue;
    // Update buffer length to actual returned size (handles case where PKCS#11
    // returns different length)
    idBuf.length = attrId.ulValueLen;

    // EC_POINT (DER OCTET STRING)
    CK_ATTRIBUTE attrPoint = {CKA_EC_POINT, NULL, 0};
    rv = self.fn_GetAttributeValue(session, obj, &attrPoint, 1);
    if (rv != CKR_OK || attrPoint.ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        attrPoint.ulValueLen == 0)
      continue;
    NSMutableData *pointBuf =
        [NSMutableData dataWithLength:attrPoint.ulValueLen];
    attrPoint.pValue = pointBuf.mutableBytes;
    rv = self.fn_GetAttributeValue(session, obj, &attrPoint, 1);
    if (rv != CKR_OK)
      continue;
    pointBuf.length = attrPoint.ulValueLen; // Update to actual returned size
    NSData *rawPoint = PKCS11DERUnwrapOctetString(pointBuf) ?: [pointBuf copy];

    // EC_PARAMS (DER OID)
    NSNumber *bits = nil;
    CK_ATTRIBUTE attrParams = {CKA_EC_PARAMS, NULL, 0};
    rv = self.fn_GetAttributeValue(session, obj, &attrParams, 1);
    if (rv == CKR_OK && attrParams.ulValueLen != CK_UNAVAILABLE_INFORMATION &&
        attrParams.ulValueLen > 0) {
      NSMutableData *paramsBuf =
          [NSMutableData dataWithLength:attrParams.ulValueLen];
      attrParams.pValue = paramsBuf.mutableBytes;
      rv = self.fn_GetAttributeValue(session, obj, &attrParams, 1);
      if (rv == CKR_OK) {
        paramsBuf.length =
            attrParams.ulValueLen; // Update to actual returned size
        bits = PKCS11KeySizeBitsFromECParams(paramsBuf);
      }
    }

    if (outKeyId)
      *outKeyId = [idBuf copy];
    if (outEcPoint)
      *outEcPoint = rawPoint;
    if (outKeySizeBits)
      *outKeySizeBits = bits;
    ok = YES;
    break;
  }

  (void)self.fn_FindObjectsFinal(session);
  if (!ok && error) {
    *error = PKCS11MakeError(
        -5,
        [NSString
            stringWithFormat:@"No public EC key matched label substring '%@'",
                             labelSubstring]);
  }
  return ok;
}

/// Finds a private key by its CKA_ID attribute.
/// Used after findPublicECKeyWithLabelSubstring to locate the corresponding
/// private key for signing operations.
///
/// @param ckaId The CKA_ID value identifying the key
/// @param session Open PKCS#11 session handle
/// @param outKey On return, the private key object handle
/// @param error Optional error output
/// @return YES if the key was found
- (BOOL)findPrivateKeyById:(NSData *)ckaId
                   session:(CK_SESSION_HANDLE)session
                 objectOut:(CK_OBJECT_HANDLE *)outKey
                     error:
                         (NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE templateAttrs[2];
  templateAttrs[0].type = CKA_CLASS;
  templateAttrs[0].pValue = &cls;
  templateAttrs[0].ulValueLen = sizeof(cls);
  templateAttrs[1].type = CKA_ID;
  templateAttrs[1].pValue = (void *)ckaId.bytes;
  templateAttrs[1].ulValueLen = (CK_ULONG)ckaId.length;

  CK_RV rv = self.fn_FindObjectsInit(session, templateAttrs, 2);
  if (rv != CKR_OK) {
    if (error)
      *error = PKCS11MakeError(
          rv,
          [NSString
              stringWithFormat:@"C_FindObjectsInit(privkey) failed: 0x%08lx",
                               (unsigned long)rv]);
    return NO;
  }

  CK_OBJECT_HANDLE obj = 0;
  CK_ULONG found = 0;
  rv = self.fn_FindObjects(session, &obj, 1, &found);
  (void)self.fn_FindObjectsFinal(session);

  if (rv != CKR_OK || found == 0) {
    if (error)
      *error = PKCS11MakeError(rv, @"Private key not found for given CKA_ID");
    return NO;
  }
  *outKey = obj;
  return YES;
}

#pragma mark - ECDSA Sign

/// Signs with ECDSA (CKM_ECDSA). The digest must already be hashed.
/// Protected by a 60-second timeout on each C_Sign call; returns error on
/// timeout.
- (BOOL)ecdsaSignWithSession:(CK_SESSION_HANDLE)session
                  privateKey:(CK_OBJECT_HANDLE)key
                      digest:(NSData *)digest
                signatureOut:(NSData *_Nullable *_Nullable)outSignature
                       error:(NSError *__autoreleasing _Nullable *_Nullable)
                                 error {
  if (![self requireNotPoisoned:error]) {
    return NO;
  }
  if (digest.length == 0) {
    if (error)
      *error = PKCS11MakeError(-4, @"digest must be non-empty");
    return NO;
  }

  CK_MECHANISM mech;
  mech.mechanism = CKM_ECDSA;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;

  CK_RV rv = self.fn_SignInit(session, &mech, key);
  if (rv != CKR_OK) {
    if (error)
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:@"C_SignInit failed: 0x%08lx",
                                         (unsigned long)rv]);
    return NO;
  }

  // ── Single C_Sign call with generous fixed buffer (with timeout) ──────
  //
  // We skip the standard two-call pattern (NULL query for length, then actual
  // sign) because some PKCS#11 implementations incorrectly consume the
  // C_SignInit state on the length query.  For CKM_ECDSA, the raw r||s
  // signature is at most 2 * ceil(keyBits/8):  P-256=64, P-384=96, P-521=132.
  // A 256-byte buffer is generous for any standard EC curve.
  //
  // Defensive copy: if the timeout fires the caller returns, but the
  // background block keeps running and would access digest after the
  // caller's scope is gone.  Give the block its own copy.
  __block CK_ULONG sigLen = 256;
  __block CK_RV rv2 = CKR_GENERAL_ERROR;
  NSMutableData *sigBuf = [NSMutableData dataWithLength:sigLen];
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  NSData *digestCopy = [digest copy];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    rv2 = self.fn_Sign(session, (CK_BYTE_PTR)digestCopy.bytes,
                       (CK_ULONG)digestCopy.length,
                       (CK_BYTE_PTR)sigBuf.mutableBytes, &sigLen);
    dispatch_semaphore_signal(sem);
  });

  long tmout = dispatch_semaphore_wait(
      sem, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC));
  if (tmout != 0) {
    os_log_error(OS_LOG_DEFAULT, "PKCS11: C_Sign TIMED OUT after 60 seconds");
    [self markPoisoned];
    if (error) {
      *error = PKCS11MakeError(-1, @"Smart card signing operation timed out. "
                                   @"The module has been poisoned — replug "
                                   @"the reader and retry.");
    }
    return NO;
  }

  if (rv2 != CKR_OK) {
    if (error)
      *error = PKCS11MakeError(
          rv2, [NSString stringWithFormat:@"C_Sign failed: 0x%08lx",
                                          (unsigned long)rv2]);
    return NO;
  }
  sigBuf.length = sigLen;

  if (outSignature) {
    *outSignature = [sigBuf copy];
  }
  return YES;
}

#pragma mark - ECDH Derive

/// Derives a shared secret via ECDH (CKM_ECDH1_DERIVE).
/// Uses CKD_NULL derivation (raw x-coordinate output).
/// Used for key agreement during card authentication.
///
/// @param session PKCS#11 session handle (must be logged in)
/// @param privateKey Private key object handle
/// @param pubKeyData Raw EC public key point of the other party
/// @param keySizeBytes Expected output key size in bytes
/// @param error Optional error output
/// @return Derived shared secret, or nil on failure
- (nullable NSData *)
    ecdhDeriveWithSession:(CK_SESSION_HANDLE)session
               privateKey:(CK_OBJECT_HANDLE)privateKey
       otherPublicKeyData:(NSData *)pubKeyData
             keySizeBytes:(NSUInteger)keySizeBytes
                    error:(NSError *__autoreleasing _Nullable *_Nullable)error {
  if (![self requireNotPoisoned:error]) {
    return nil;
  }
  if (!self.fn_DeriveKey) {
    if (error)
      *error = PKCS11MakeError(-6, @"C_DeriveKey not available via dlsym");
    return nil;
  }
  if (pubKeyData.length == 0) {
    if (error)
      *error = PKCS11MakeError(-6, @"otherPublicKeyData must be non-empty");
    return nil;
  }

  // CKM_ECDH1_DERIVE + CKD_NULL: derive raw Z value (X coordinate of shared EC
  // point). No KDF applied — the caller (ctkbind) applies its own KDF to the
  // raw Z value.
  CK_ECDH1_DERIVE_PARAMS params;
  memset(&params, 0, sizeof(params));
  params.kdf = CKD_NULL;
  params.ulSharedDataLen = 0;
  params.pSharedData = NULL;
  params.ulPublicDataLen = (CK_ULONG)pubKeyData.length;
  params.pPublicData = (CK_BYTE_PTR)pubKeyData.bytes;

  CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &params, sizeof(params)};

  // Derived key template: session-only generic secret, extractable, not
  // sensitive.
  CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
  CK_KEY_TYPE ktype = CKK_GENERIC_SECRET;
  CK_BBOOL bFalse = CK_FALSE;
  CK_BBOOL bTrue = CK_TRUE;
  CK_ULONG vlen = (CK_ULONG)keySizeBytes;

  CK_ATTRIBUTE tmpl[] = {
      {CKA_CLASS, &cls, sizeof(cls)},
      {CKA_KEY_TYPE, &ktype, sizeof(ktype)},
      {CKA_TOKEN, &bFalse, sizeof(bFalse)},     // session object, not stored on
                                                // card
      {CKA_SENSITIVE, &bFalse, sizeof(bFalse)}, // allow CKA_VALUE extraction
      {CKA_EXTRACTABLE, &bTrue, sizeof(bTrue)},
      {CKA_VALUE_LEN, &vlen, sizeof(vlen)},
  };

  CK_OBJECT_HANDLE derivedKey = 0;
  CK_RV rv = self.fn_DeriveKey(session, &mech, privateKey, tmpl,
                               sizeof(tmpl) / sizeof(tmpl[0]), &derivedKey);
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT, "PKCS11: C_DeriveKey(ECDH) failed: 0x%lx",
                 (unsigned long)rv);
    if (error)
      *error = PKCS11MakeError(
          rv, [NSString
                  stringWithFormat:@"C_DeriveKey(ECDH1_DERIVE) failed: 0x%08lx",
                                   (unsigned long)rv]);
    return nil;
  }
  os_log(OS_LOG_DEFAULT, "PKCS11: C_DeriveKey OK, derived key handle=0x%lx",
         (unsigned long)derivedKey);

  // Read raw Z value (the X coordinate of the shared EC point) from derived key
  // object.
  CK_ATTRIBUTE valAttr = {CKA_VALUE, NULL, 0};
  rv = self.fn_GetAttributeValue(session, derivedKey, &valAttr, 1);
  if (rv != CKR_OK || valAttr.ulValueLen == 0 ||
      valAttr.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: CKA_VALUE size query failed: rv=0x%lx len=%lu",
                 (unsigned long)rv, (unsigned long)valAttr.ulValueLen);
    if (error)
      *error = PKCS11MakeError(
          rv,
          @"C_GetAttributeValue(CKA_VALUE) size query failed for derived key");
    return nil;
  }

  NSMutableData *secret = [NSMutableData dataWithLength:valAttr.ulValueLen];
  valAttr.pValue = secret.mutableBytes;
  rv = self.fn_GetAttributeValue(session, derivedKey, &valAttr, 1);
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT, "PKCS11: CKA_VALUE read failed: 0x%lx",
                 (unsigned long)rv);
    if (error)
      *error = PKCS11MakeError(
          rv, [NSString stringWithFormat:
                            @"C_GetAttributeValue(CKA_VALUE) failed: 0x%08lx",
                            (unsigned long)rv]);
    return nil;
  }
  secret.length = valAttr.ulValueLen; // Update to actual returned size

  os_log(OS_LOG_DEFAULT, "PKCS11: ECDH derive OK, shared secret length=%lu",
         (unsigned long)secret.length);
  return [secret copy];
}

#pragma mark - Diagnostics

/// Logs all supported cryptographic mechanisms for a slot to os_log.
/// Used for debugging to verify which algorithms the token supports.
///
/// @param slot PKCS#11 slot ID to query
- (void)logMechanismsForSlot:(CK_SLOT_ID)slot {
  if (atomic_load(&_poisoned)) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: logMechanismsForSlot skipped — module is poisoned");
    return;
  }
  if (!self.fn_GetMechanismList) {
    os_log(OS_LOG_DEFAULT,
           "PKCS11: C_GetMechanismList not available via dlsym");
    return;
  }

  CK_ULONG count = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  CK_RV rv = self.fn_GetMechanismList(slot, NULL, &count);
#pragma clang diagnostic pop
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: C_GetMechanismList(count) slot=0x%lx failed: 0x%lx",
                 (unsigned long)slot, (unsigned long)rv);
    return;
  }
  if (count == 0) {
    os_log(OS_LOG_DEFAULT, "PKCS11: slot 0x%lx has 0 mechanisms",
           (unsigned long)slot);
    return;
  }

  NSMutableData *mechBuf =
      [NSMutableData dataWithLength:count * sizeof(CK_MECHANISM_TYPE)];
  rv = self.fn_GetMechanismList(
      slot, (CK_MECHANISM_TYPE_PTR)mechBuf.mutableBytes, &count);
  if (rv != CKR_OK) {
    os_log_error(OS_LOG_DEFAULT,
                 "PKCS11: C_GetMechanismList(list) slot=0x%lx failed: 0x%lx",
                 (unsigned long)slot, (unsigned long)rv);
    return;
  }

  const CK_MECHANISM_TYPE *mechs = (const CK_MECHANISM_TYPE *)mechBuf.bytes;
  os_log(OS_LOG_DEFAULT,
         "PKCS11: slot 0x%lx supports %lu mechanisms:", (unsigned long)slot,
         (unsigned long)count);
  for (CK_ULONG i = 0; i < count; i++) {
    CK_MECHANISM_TYPE mech = mechs[i];
    CK_FLAGS flags = 0;
    if (self.fn_GetMechanismInfo) {
      CK_MECHANISM_INFO info = {0, 0, 0};
      if (self.fn_GetMechanismInfo(slot, mech, &info) == CKR_OK) {
        flags = info.flags;
      }
    }
    const char *name = "?";
    switch (mech) {
    case CKM_EC_KEY_PAIR_GEN:
      name = "CKM_EC_KEY_PAIR_GEN";
      break;
    case CKM_ECDSA:
      name = "CKM_ECDSA";
      break;
    case CKM_ECDSA_SHA1:
      name = "CKM_ECDSA_SHA1";
      break;
    case CKM_ECDSA_SHA256:
      name = "CKM_ECDSA_SHA256";
      break;
    case CKM_ECDSA_SHA384:
      name = "CKM_ECDSA_SHA384";
      break;
    case CKM_ECDSA_SHA512:
      name = "CKM_ECDSA_SHA512";
      break;
    case CKM_ECDH1_DERIVE:
      name = "CKM_ECDH1_DERIVE *** ECDH AVAILABLE ***";
      break;
    case CKM_ECDH1_COFACTOR_DERIVE:
      name = "CKM_ECDH1_COFACTOR_DERIVE *** ECDH AVAILABLE ***";
      break;
    }
    os_log(OS_LOG_DEFAULT,
           "PKCS11:   [%lu] 0x%08lx %{public}s flags=0x%08lx%{public}s",
           (unsigned long)i, (unsigned long)mech, name, (unsigned long)flags,
           (flags & CKF_DERIVE) ? " (DERIVE)" : "");
  }
}

@end
