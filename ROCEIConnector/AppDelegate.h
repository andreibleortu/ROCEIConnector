//
// AppDelegate.h
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//
// Main application controller for RO CEI Connector.
// Provides GUI and CLI interfaces for:
// - Registering persistent Romanian eID tokens
// - Installing CA certificates
// - Managing CryptoTokenKit extensions
// - Testing PKCS#11 operations via XPC helper
//

#import <Cocoa/Cocoa.h>

/// Main application delegate for RO CEI Connector.
/// Handles both GUI and command-line modes of operation.
@interface AppDelegate : NSObject <NSApplicationDelegate>


@end

