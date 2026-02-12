//
// ROCEIExtensionShared.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Shared utility functions for the CryptoTokenKit extension
//

#import <Foundation/Foundation.h>
#import <os/log.h>

NS_ASSUME_NONNULL_BEGIN

/// Returns the cache directory URL for storing certificate and key ID data.
/// Used to cache certificate DER data and CKA_ID between card insertions so the token
/// can be published immediately on next insertion without requiring PIN entry first.
/// @return Cache directory URL (~/Library/Caches/com.andrei.rocei.connector.extension/)
///
/// NOTE: This is intentionally defined as static inline to avoid linkage issues
/// across multiple translation units. Each .m file that includes this header gets
/// its own copy, which the compiler can optimize via inlining.
static inline NSURL *ROCEICacheDirURL(void) {
    NSArray<NSURL *> *urls = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask];
    NSURL *base = urls.firstObject ?: [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    return [base URLByAppendingPathComponent:@"com.andrei.rocei.connector.extension" isDirectory:YES];
}

/// Reads a file from the cache directory.
/// @param filename Name of the file to read (e.g., "auth_cert.der")
/// @return File contents, or nil if file doesn't exist or read fails
static inline NSData *_Nullable ROCEIReadCachedFile(NSString *filename) {
  NSURL *dir = ROCEICacheDirURL();
  NSURL *file = [dir URLByAppendingPathComponent:filename isDirectory:NO];
  return [NSData dataWithContentsOfURL:file];
}

/// Writes data to a file in the cache directory with restricted permissions.
/// Uses atomic write and POSIX mode 0600 (owner read/write only) to protect
/// against unauthorized access by other processes.  This protects against:
/// - Unauthorized access by other processes to cached CKA_ID (reveals key slot)
/// - File swapping attacks where malware replaces certificates to redirect auth
///
/// NOTE: NSDataWritingFileProtectionComplete is iOS-only (Data Protection API)
/// and has no effect on macOS.  We use POSIX file permissions instead.
///
/// @param filename Name of the file (e.g., "auth_cert.der", "auth_keyid.bin")
/// @param data Data to write
/// @param error Optional error output
/// @return YES if write succeeded, NO otherwise
static inline BOOL ROCEIWriteCachedFile(NSString *filename, NSData *data,
                                        NSError *_Nullable *_Nullable error) {
  NSURL *dir = ROCEICacheDirURL();
  NSError *mkdirError = nil;
  // Create directory with 0700 permissions (owner only)
  NSDictionary *dirAttrs = @{NSFilePosixPermissions : @(0700)};
  if (![[NSFileManager defaultManager] createDirectoryAtURL:dir
                                withIntermediateDirectories:YES
                                                 attributes:dirAttrs
                                                      error:&mkdirError]) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to create cache directory: %{public}@",
                 mkdirError);
    if (error)
      *error = mkdirError;
    return NO;
  }

  NSURL *file = [dir URLByAppendingPathComponent:filename isDirectory:NO];
  NSError *writeError = nil;
  // Atomic write to prevent partial reads
  if (![data writeToURL:file options:NSDataWritingAtomic error:&writeError]) {
    os_log_error(OS_LOG_DEFAULT,
                 "Extension: Failed to write cache file %{public}@: %{public}@",
                 filename, writeError);
    if (error)
      *error = writeError;
    return NO;
  }

  // Restrict file permissions to owner read/write only (0600)
  NSDictionary *fileAttrs = @{NSFilePosixPermissions : @(0600)};
  [[NSFileManager defaultManager] setAttributes:fileAttrs
                                   ofItemAtPath:file.path
                                          error:nil];

  os_log(OS_LOG_DEFAULT,
         "Extension: Successfully cached %{public}@ (%lu bytes) with restricted "
         "permissions",
         filename, (unsigned long)data.length);
  return YES;
}

NS_ASSUME_NONNULL_END

