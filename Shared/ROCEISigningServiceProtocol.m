//
// ROCEISigningServiceProtocol.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import "ROCEISigningServiceProtocol.h"

@implementation ROCEICertificateInfo

/// Initializes certificate info with DER-encoded certificate and associated key
/// metadata.
/// @param certificateDER X.509 certificate in DER format (read from PKCS#11
/// token)
/// @param keyID PKCS#11 CKA_ID bytes that uniquely identify the key pair
/// @param label Human-readable label for the certificate/key (e.g., "RO CEI
/// Authentication Certificate")
/// @param keySizeBits Key size in bits (256 for secp256r1, 384 for secp384r1)
/// @param publicKeyData Uncompressed EC public key point (0x04 || X || Y) for
/// key-only items
- (instancetype)initWithCertificateDER:(NSData *)certificateDER
                                 keyID:(NSData *)keyID
                                 label:(NSString *)label
                           keySizeBits:(NSUInteger)keySizeBits
                         publicKeyData:(nullable NSData *)publicKeyData {
  if (self = [super init]) {
    _certificateDER = [certificateDER copy];
    _keyID = [keyID copy];
    _label = [label copy];
    _keySizeBits = keySizeBits;
    _publicKeyData = [publicKeyData copy];
  }
  return self;
}

#pragma mark - NSSecureCoding

/// Indicates that this class supports secure coding (required for XPC transfer)
+ (BOOL)supportsSecureCoding {
  return YES;
}

/// Encodes certificate info for XPC transfer.
/// All properties are encoded with their respective types to ensure type
/// safety.
- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:self.certificateDER forKey:@"certificateDER"];
  [coder encodeObject:self.keyID forKey:@"keyID"];
  [coder encodeObject:self.label forKey:@"label"];
  [coder encodeInteger:self.keySizeBits forKey:@"keySizeBits"];
  [coder encodeObject:self.publicKeyData forKey:@"publicKeyData"];
}

/// Decodes certificate info from XPC transfer with type checking.
/// Returns nil if required fields are missing or have incorrect types.
- (nullable instancetype)initWithCoder:(NSCoder *)coder {
  NSData *certificateDER = [coder decodeObjectOfClass:[NSData class]
                                               forKey:@"certificateDER"];
  NSData *keyID = [coder decodeObjectOfClass:[NSData class] forKey:@"keyID"];
  NSString *label = [coder decodeObjectOfClass:[NSString class]
                                        forKey:@"label"];
  NSUInteger keySizeBits = [coder decodeIntegerForKey:@"keySizeBits"];
  NSData *publicKeyData = [coder decodeObjectOfClass:[NSData class]
                                              forKey:@"publicKeyData"];

  // Validate required fields - certificate, keyID, and label are mandatory
  if (!certificateDER || !keyID || !label) {
    return nil;
  }

  return [self initWithCertificateDER:certificateDER
                                keyID:keyID
                                label:label
                          keySizeBits:keySizeBits
                        publicKeyData:publicKeyData];
}

/// Returns a debug description with label, key ID length, key size, and cert size.
- (NSString *)description {
  return
      [NSString stringWithFormat:@"<ROCEICertificateInfo: label=%@ keyID=%lu "
                                 @"bytes keySizeBits=%lu cert=%lu bytes>",
                                 self.label, (unsigned long)self.keyID.length,
                                 (unsigned long)self.keySizeBits,
                                 (unsigned long)self.certificateDER.length];
}

@end
