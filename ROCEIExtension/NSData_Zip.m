//
// NSData_Zip.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <Foundation/Foundation.h>
#import <os/log.h>
#import <zlib.h>
#import <zconf.h>

#import "Token.h"

// Maximum decompressed size (1 MB) to prevent zip bomb attacks.
// Certificate data from smart cards should never exceed this limit.
static const NSUInteger kMaxDecompressedSize = 1024 * 1024; // 1 MB

NS_ASSUME_NONNULL_BEGIN

@implementation NSData(Zip)

/// Determines the zlib window size based on the data's magic bytes.
/// Gzip streams (0x1F 0x8B) use MAX_WBITS + 16; raw deflate uses
/// MAX_WBITS + 32 for automatic header detection.
- (int)getWindowSize {
    int windowSize = MAX_WBITS;
    uint8_t *bytes = (uint8_t *)self.bytes;

    if (self.length > 2 && bytes[0] == 0x1F && bytes[1] == 0x8B) //gzip
        windowSize += 0x10;
    else
        windowSize += 0x20;

    return windowSize;
}

/// Decompresses the receiver using zlib inflate.
/// Grows the output buffer as needed, capped at kMaxDecompressedSize
/// to defend against zip bomb attacks.
///
/// @return Decompressed data, or nil on error or size limit
- (nullable NSData *)inflate {
    z_stream dstream;
    int windowSize = [self getWindowSize];

    dstream.zalloc = (alloc_func)0;
    dstream.zfree = (free_func)0;
    dstream.opaque = (voidpf)0;
    /* Input not altered , so de-const-casting ok*/
    dstream.next_in  = (Bytef*)self.bytes;
    dstream.avail_in = (uInt)self.length;
    int err = inflateInit2(&dstream, windowSize);
    if (err != Z_OK)
        return nil;

    NSUInteger offset = 0;
    NSMutableData *data = [NSMutableData dataWithLength:1024];
    for (;;) {
        dstream.next_out = [data mutableBytes] + offset;
        dstream.avail_out = (uInt)(data.length - offset);
        err = inflate(&dstream, Z_NO_FLUSH);

        if (err == Z_OK) {
            offset = data.length;
            NSUInteger newSize = data.length + data.length / 2;
            
            // SECURITY: Defend against zip bombs by limiting decompressed size
            if (newSize > kMaxDecompressedSize) {
                os_log_error(OS_LOG_DEFAULT,
                             "NSData+Zip: Decompressed data exceeds %zu bytes (zip bomb?). "
                             "Compressed size: %zu bytes, attempted decompressed size: %zu bytes",
                             kMaxDecompressedSize, self.length, newSize);
                inflateEnd(&dstream);
                return nil;
            }
            
            [data setLength:newSize];
        }
        else if (err == Z_STREAM_END) {
            break;
        }
        else {
            inflateEnd(&dstream);
            return nil;
        }
    }

    [data setLength:dstream.total_out];
    inflateEnd(&dstream);
    return data;
}

@end

NS_ASSUME_NONNULL_END

