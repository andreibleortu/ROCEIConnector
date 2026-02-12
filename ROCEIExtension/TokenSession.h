//
// TokenSession.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//
// This file declares session handlers for Romanian eID token operations.
// Sessions manage the lifecycle of cryptographic operations (sign, decrypt,
// key exchange) requested by applications.
//

#import "Token.h"

NS_ASSUME_NONNULL_BEGIN

#if 0 // DISABLED: smartcard auto-detection — persistent/explicit registration is active
/// Internal session state tracking for smartcard-based tokens.
/// Tracks whether the user has authenticated and whether the authentication
/// has been consumed by an operation.
@interface ROCEISession()

/// Authentication state enum
typedef NS_ENUM(NSInteger, ROCEIAuthState) {
    ROCEIAuthStateUnauthorized = 0,              ///< No PIN entered yet
    ROCEIAuthStateFreshlyAuthorized = 1,         ///< PIN just entered, not yet used
    ROCEIAuthStateAuthorizedButAlreadyUsed = 2,  ///< PIN entered and consumed by an operation
};

/// Current authentication state
@property ROCEIAuthState authState;

@end

/// Represents a PIN authentication operation for smartcard tokens.
/// This operation prompts the user for their PIN and validates it against
/// the card.
@interface ROCEIAuthOperation : TKTokenSmartCardPINAuthOperation

/// Initializes an authentication operation for the given session.
/// @param session The smartcard token session
/// @return Initialized auth operation instance
- (instancetype)initWithSession:(ROCEISession *)session;

/// The session associated with this authentication operation
@property (readonly) ROCEISession *session;

@end
#endif // DISABLED: smartcard mode


NS_ASSUME_NONNULL_END
