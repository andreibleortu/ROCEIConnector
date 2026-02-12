//
// Token.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <CryptoTokenKit/TKSmartCardToken.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark TKSmartCard utility extension for sending/receiving TKBERTLVRecord-formatted APDUs

/// Extension category for TKSmartCard that provides BER-TLV APDU helpers.
/// These methods simplify communication with Romanian eID cards using ISO 7816-4
/// TLV data structures.
@interface TKSmartCard(ROCEIDataFormat)

/// Sends an APDU command with BER-TLV formatted data and expects a TLV response.
///
/// @param ins Instruction byte (INS) for the APDU command
/// @param p1 Parameter 1 (P1) byte for the APDU command
/// @param p2 Parameter 2 (P2) byte for the APDU command
/// @param request Optional TLV record to send as APDU data field
/// @param expectedTag Expected TLV tag in the response (validated)
/// @param sw Output parameter for the status word (SW1||SW2)
/// @param error Optional error output
/// @return Parsed TLV record from response, or nil on error or tag mismatch
- (nullable TKTLVRecord *)sendIns:(UInt8)ins p1:(UInt8)p1 p2:(UInt8)p2 request:(nullable TKTLVRecord *)request expectedTag:(TKTLVTag)expectedTag sw:(UInt16 *)sw error:(NSError **)error;

/// Reads all TLV records for a given object ID from the card.
///
/// @param objectID The token object ID identifying which object to read
/// @param error Optional error output
/// @return Array of TLV records contained in the object, or nil on error
- (nullable NSArray<TKTLVRecord *> *)recordsOfObject:(TKTokenObjectID)objectID error:(NSError **)error;

@end

#pragma mark PIV implementation of TKToken classes

/// Extended keychain key class that stores additional metadata for Romanian eID
/// keys. This subclass adds support for certificate associations and
/// per-operation authentication requirements.
@interface ROCEIKeychainKey : TKTokenKeychainKey

/// Designated initializer for a keychain key with certificate and authentication
/// settings.
///
/// @param certificateRef Reference to the certificate associated with this key
/// @param objectID Unique object ID for this key (typically the CKA_ID from
/// PKCS#11)
/// @param certificateID Object ID of the associated certificate Item
/// @param alwaysAuthenticate If YES, requires PIN for every operation
/// (ROCEIConstraintPINAlways); if NO, allows cached authentication
/// (ROCEIConstraintPIN)
/// @return Initialized key instance
- (instancetype)initWithCertificate:(SecCertificateRef)certificateRef objectID:(TKTokenObjectID)objectID certificateID:(TKTokenObjectID)certificateID alwaysAuthenticate:(BOOL)alwaysAuthenticate NS_DESIGNATED_INITIALIZER;

/// Base initializer is unavailable — use designated initializer instead
- (instancetype)initWithCertificate:(nullable SecCertificateRef)certificateRef objectID:(TKTokenObjectID)objectID NS_UNAVAILABLE;

/// Object ID of the associated certificate in the token's keychain
@property (readonly) TKTokenObjectID certificateID;

/// Whether this key requires authentication for every operation (YES) or allows
/// cached authentication (NO)
@property (readonly) BOOL alwaysAuthenticate;

/// PIV key reference tag (single byte identifier)
@property (readonly) UInt8 keyID;

/// PIV algorithm identifier (per SP 800-78-4 Table 6-2 and 6-3):
/// - 0x11 for EC P-256, 0x14 for EC P-384
/// - 0x06 for RSA 1024, 0x07 for RSA 2048
@property (readonly) UInt8 algID;

@end

/// Token operation constraint requiring PIN authentication (allows caching)
static const TKTokenOperationConstraint ROCEIConstraintPIN = @"PIN";

/// Token operation constraint requiring PIN for every operation (no caching)
static const TKTokenOperationConstraint ROCEIConstraintPINAlways = @"PINAlways";

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration is active
@class ROCEIDriver;
@class ROCEICard;
@class ROCEISession;

@interface ROCEISession : TKSmartCardTokenSession<TKTokenSessionDelegate>
- (instancetype)initWithToken:(TKToken *)token delegate:(id<TKTokenSessionDelegate>)delegate NS_UNAVAILABLE;

- (instancetype)initWithToken:(ROCEICard *)token;
@property (readonly) ROCEICard *ROCEICard;

@end

@interface ROCEICard : TKSmartCardToken<TKTokenDelegate>
- (instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID tokenDriver:(TKSmartCardTokenDriver *)tokenDriver delegate:(id<TKTokenDelegate>)delegate NS_UNAVAILABLE;

- (nullable instancetype)initWithSmartCard:(TKSmartCard *)smartCard AID:(nullable NSData *)AID PIVDriver:(ROCEIDriver *)tokenDriver error:(NSError **)error;
@property (readonly) ROCEIDriver *driver;

@end

@interface ROCEIDriver : TKSmartCardTokenDriver<TKSmartCardTokenDriverDelegate>
@end
#endif // DISABLED: smartcard mode

/// Token driver for persistent (non-smartcard) Romanian eID tokens.
/// This driver manages token registrations that persist across card removals
/// and system reboots. Uses PKCS#11 to access the physical card when needed.
@interface ROCEIPersistentDriver : TKTokenDriver<TKTokenDriverDelegate>
@end

/// Session handler for persistent token operations.
/// Manages cryptographic operations (sign, decrypt, key exchange) requested by
/// applications. Communicates with the XPC helper service to perform PKCS#11
/// operations outside the sandbox.
@interface ROCEIPersistentSession : TKTokenSession<TKTokenSessionDelegate>

/// Base initializer unavailable — use designated initializer instead
- (instancetype)initWithToken:(TKToken *)token delegate:(id<TKTokenSessionDelegate>)delegate NS_UNAVAILABLE;

/// Designated initializer for session creation.
///
/// @param token The persistent token instance that owns this session
/// @return Initialized session instance
- (instancetype)initWithToken:(TKToken *)token;
@end

/// Represents a persistent Romanian eID token registration.
/// Unlike smartcard tokens (ROCEICard), persistent tokens remain registered
/// even when the card is removed. They are configured by ROCEIConnector.app
/// with PKCS#11 module paths and optionally pre-fetched certificate data for
/// fast enumeration.
@interface ROCEIPersistentCard : TKToken<TKTokenDelegate>

/// Initializes a persistent token with the given instance ID.
/// Called by CryptoTokenKit when loading a token configuration.
///
/// @param tokenDriver The token driver instance
/// @param instanceID Unique instance ID for this token (e.g., "rocei-pkcs11")
/// @param error Optional error output
/// @return Initialized token instance, or nil on error
- (instancetype)initWithTokenDriver:(TKTokenDriver *)tokenDriver instanceID:(TKTokenInstanceID)instanceID error:(NSError **)error;

/// Unique instance ID for this token configuration
@property (readonly) TKTokenInstanceID instanceID;
@end

NS_ASSUME_NONNULL_END
