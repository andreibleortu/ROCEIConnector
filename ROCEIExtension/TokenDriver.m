//
// TokenDriver.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//
// Token driver implementations for Romanian eID cards.
// The driver is responsible for:
// - Loading when CryptoTokenKit starts
// - Creating token instances when cards are detected
// - Managing the token lifecycle
//

#import <Foundation/Foundation.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <os/log.h>

#import "Token.h"

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration is active
@interface ROCEIDriver ()
@end

@implementation ROCEIDriver

/// Called when the driver class is loaded into memory.
/// This happens once when CryptoTokenKit initializes.
+ (void)load {
    os_log(OS_LOG_DEFAULT, "Extension driver loaded");
}

/// Called by the system when the extension is activated.
/// For token drivers, we complete the request immediately so the system can
/// proceed with the TKSmartCardTokenDriver lifecycle.
///
/// @param context The extension context provided by the system
- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
    os_log(OS_LOG_DEFAULT, "Extension driver beginRequestWithExtensionContext - completing immediately");
    // For token drivers, complete the generic extension request immediately
    // so the system can proceed with TKSmartCardTokenDriver delegate lifecycle
    [context completeRequestReturningItems:@[] completionHandler:^(BOOL expired) {
        os_log(OS_LOG_DEFAULT, "Extension driver extension request completed, expired=%d", expired);
    }];
}

/// Designated initializer for the token driver.
/// Sets self as the delegate to receive token creation callbacks.
- (instancetype)init {
    if (self = [super init]) {
        self.delegate = self;
        os_log(OS_LOG_DEFAULT, "Extension driver init");
    }
    return self;
}

/// Converts binary data to uppercase hexadecimal string.
/// Used for logging AIDs and ATRs.
///
/// @param data Binary data to convert
/// @return Hexadecimal string representation
static NSString *ROCEIHexStringFromData(NSData *data) {
    if (data.length == 0) {
        return @"";
    }
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hex appendFormat:@"%02X", bytes[i]];
    }
    return hex;
}

/// Creates a token instance when a matching smartcard is detected.
/// Called by CryptoTokenKit when a card with the registered AID is inserted.
///
/// @param driver The token driver instance (unused)
/// @param smartCard The detected smartcard instance
/// @param AID Application ID that was matched (may be nil)
/// @param error Optional error output
/// @return A new ROCEICard token instance, or nil on error
- (TKSmartCardToken *)tokenDriver:(TKSmartCardTokenDriver *)driver createTokenForSmartCard:(TKSmartCard *)smartCard AID:(NSData *)AID error:(NSError * _Nullable __autoreleasing *)error {
    NSString *aidHex = AID ? ROCEIHexStringFromData(AID) : @"(nil)";
    NSString *atrHex = @"(nil)";
    if (smartCard.slot.ATR.bytes.length > 0) {
        atrHex = ROCEIHexStringFromData(smartCard.slot.ATR.bytes);
    }
    os_log(OS_LOG_DEFAULT, "Extension driver createTokenForSmartCard slot=%{public}@ AID=%{public}@ ATR=%{public}@",
           smartCard.slot.name, aidHex, atrHex);
    return [[ROCEICard alloc] initWithSmartCard:smartCard AID:AID PIVDriver:self error:error];
}

@end
#endif // DISABLED: smartcard mode

@interface ROCEIPersistentDriver ()
@end

@implementation ROCEIPersistentDriver

/// Called when the driver class is loaded into memory.
/// This happens once when CryptoTokenKit initializes.
+ (void)load {
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver loaded");
}

/// Called by the system when the extension is activated.
/// For persistent token drivers, we complete the request immediately so the
/// system can proceed with token enumeration.
///
/// @param context The extension context provided by the system
- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context {
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver beginRequestWithExtensionContext - completing immediately");
    // For persistent token drivers, complete the generic extension request immediately
    // so the system can proceed with TKTokenDriver delegate lifecycle
    [context completeRequestReturningItems:@[] completionHandler:^(BOOL expired) {
        os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver extension request completed, expired=%d", expired);
    }];
}

/// Designated initializer for the persistent token driver.
/// Sets self as the delegate to receive token creation callbacks.
- (instancetype)init {
    if (self = [super init]) {
        self.delegate = self;
        os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver init");
    }
    return self;
}

/// Creates a token instance for the given configuration.
/// Called by CryptoTokenKit when loading a persistent token registration.
///
/// @param driver The token driver instance (unused)
/// @param configuration Token configuration containing instance ID and metadata
/// @param error Optional error output
/// @return A new ROCEIPersistentCard token instance, or nil on error
- (TKToken *)tokenDriver:(TKTokenDriver *)driver tokenForConfiguration:(TKTokenConfiguration *)configuration error:(NSError * _Nullable __autoreleasing *)error {
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver tokenForConfiguration instanceID=%{public}@", configuration.instanceID);
    return [[ROCEIPersistentCard alloc] initWithTokenDriver:driver instanceID:configuration.instanceID error:error];
}

/// Called when a token is being terminated.
/// Allows cleanup of token-specific resources.
///
/// @param driver The token driver instance (unused)
/// @param token The token being terminated
- (void)tokenDriver:(TKTokenDriver *)driver terminateToken:(TKToken *)token {
    os_log(OS_LOG_DEFAULT, "ROCEIPersistentDriver terminateToken");
}

@end
