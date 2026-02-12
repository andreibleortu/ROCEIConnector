//
// ROCEISigningServiceProtocol.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Certificate and key information returned from ROCEIHelper.
/// Transferred over XPC via NSSecureCoding.
/// Contains the DER-encoded certificate, PKCS#11 key ID, label, key size,
/// and optionally the raw EC public key point.
@interface ROCEICertificateInfo : NSObject <NSSecureCoding>

/// X.509 certificate in DER encoding, read from the PKCS#11 token.
@property (nonatomic, strong) NSData *certificateDER;
/// PKCS#11 CKA_ID bytes uniquely identifying the key pair.
@property (nonatomic, strong) NSData *keyID;
/// Human-readable label (e.g., "RO CEI Authentication Certificate").
@property (nonatomic, strong) NSString *label;
/// Key size in bits (256 for secp256r1, 384 for secp384r1).
@property (nonatomic, assign) NSUInteger keySizeBits;
/// Uncompressed EC public key point (0x04 || X || Y), if available.
@property (nonatomic, strong, nullable) NSData *publicKeyData;

- (instancetype)initWithCertificateDER:(NSData *)certificateDER
                                 keyID:(NSData *)keyID
                                 label:(NSString *)label
                           keySizeBits:(NSUInteger)keySizeBits
                         publicKeyData:(nullable NSData *)publicKeyData;

@end

/// Progress reporting protocol (implemented by the connector, called by the helper)
@protocol ROCEIProgressProtocol
- (void)reportProgress:(NSString *)step;
@end

/// XPC protocol for ROCEI signing service (implemented by ROCEIHelper)
@protocol ROCEISigningServiceProtocol

/// Enumerate certificates and keys from PKCS#11 token (used during registration)
/// @param slot The PKCS#11 slot ID (e.g., @(0x1) for authentication slot)
/// @param reply Completion handler with array of certificate info or error
- (void)enumerateCertificatesWithSlot:(NSNumber *)slot
                                reply:(void (^)(NSArray<ROCEICertificateInfo *> * _Nullable items, NSError * _Nullable error))reply;

/// Sign digest with private key (used during CTK signing operations)
/// @param digest The pre-hashed digest to sign (32 bytes for SHA-256, 48 bytes for SHA-384)
/// @param keyID The PKCS#11 CKA_ID of the private key
/// @param slot The PKCS#11 slot ID
/// @param pinData The user's PIN as NSData (for secure handling) - will be cleared after use
/// @param reply Completion handler with DER-encoded signature or error
- (void)signDigest:(NSData *)digest
         withKeyID:(NSData *)keyID
              slot:(NSNumber *)slot
           pinData:(NSData *)pinData
             reply:(void (^)(NSData * _Nullable signature, NSError * _Nullable error))reply;

/// Reset PKCS#11 state: calls C_Finalize to close all sessions and shut down the library.
/// The module will be re-initialized on next use.
/// @param reply Completion handler with success flag and descriptive message
- (void)resetPKCS11WithReply:(void (^)(BOOL success, NSString *message))reply;

/// Health check / connection test
/// @param reply Completion handler with alive status and version string
- (void)pingWithReply:(void (^)(BOOL alive, NSString *version))reply;

@end

NS_ASSUME_NONNULL_END
