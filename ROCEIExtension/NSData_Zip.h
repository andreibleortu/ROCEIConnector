//
// NSData_Zip.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <Foundation/Foundation.h>

/// Category on NSData for zlib decompression of smart card certificate data.
/// PIV / eID cards may store certificates in compressed (gzip or raw deflate)
/// format. This category decompresses them transparently.
@interface NSData (Zip)

/// Decompresses the receiver using zlib inflate.
/// Auto-detects gzip (0x1F 0x8B header) vs raw deflate.
/// Returns nil on error or if the decompressed size exceeds 1 MB.
- (nullable NSData *)inflate;

@end
