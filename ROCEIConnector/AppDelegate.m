//
// AppDelegate.m
// RO CEI Connector
//
// Copyright (C) 2026 Andrei-Alexandru Bleorțu
// SPDX-License-Identifier: AGPL-3.0-only
//
// Based on Apple's PIVToken sample code (Copyright 2016 Apple Inc.)
// Modified for Romanian eID card support
//

#import "AppDelegate.h"
#import <CommonCrypto/CommonDigest.h>
#import <CryptoTokenKit/CryptoTokenKit.h>
#import <Security/Security.h>
#import <os/log.h>
@import ServiceManagement;
#import "../Shared/ROCEISigningServiceProtocol.h"
#import "../Shared/PKCS11/PKCS11.h"

/// Flipped NSClipView so NSStackView grows top-down.
@interface NSFlippedClipView : NSClipView
@end
@implementation NSFlippedClipView
- (BOOL)isFlipped {
  return YES;
}
@end

/// A single GUI status row: spinner -> icon + title + summary + optional
/// Details button.
@interface ROCEIStatusRow : NSObject
@property(strong) NSView *rowView;
@property(strong) NSProgressIndicator *spinner;
@property(strong) NSImageView *iconView;
@property(strong) NSTextField *titleLabel;
@property(strong) NSTextField *summaryLabel;
@property(strong) NSButton *detailsButton;
@property(copy) NSString *rawOutput;
@end
@implementation ROCEIStatusRow
@end

@interface AppDelegate () <ROCEIProgressProtocol>

@property(strong) NSWindow *window;
// Setup buttons
@property(strong) NSButton *installCertsButton;
@property(strong) NSButton *registerButton;
// Status
@property(strong) NSButton *checkButton;
// Advanced section
@property(strong) NSButton *advancedToggle;
@property(strong) NSView *advancedContainer;
@property(assign) BOOL advancedVisible;
@property(strong) NSButton *setupButton; // Test Sign
@property(strong) NSButton *resetCtkdButton;
@property(strong) NSButton *verifyButton;
@property(strong) NSButton *deregisterTokenButton;
@property(strong) NSButton *unregisterButton;
@property(strong) NSButton *registerExtButton;
@property(strong) NSButton *extensionInfoButton;
@property(strong) NSButton *killPkcs11Button;
@property(strong) NSButton *resetPKCS11Button;
@property(strong) NSButton *uninstallButton;
// Results GUI
@property(strong) NSBox *resultsBox;        // Container for status rows
@property(strong) NSView *resultsView;      // View holding row subviews
@property(strong) NSMutableArray<ROCEIStatusRow *> *statusRows;
@property(strong) NSBox *detailBox;         // Detail text container
@property(strong) NSTextView *detailView;
@property(strong) NSView *outputContainer; // parent for results + detail
// CLI
@property(assign) BOOL cliMode;
@property(copy) NSString *cliSlot;
@property(copy) NSArray<NSString *> *cliActions;
@property(nonatomic, strong) NSXPCConnection *helperConnection;

// Status row methods
- (NSUInteger)addRowWithTitle:(NSString *)title waiting:(BOOL)waiting;
- (void)startRow:(NSUInteger)index;

@end

@implementation AppDelegate

/// Application entry point. In CLI mode, runs requested actions and exits.
/// In GUI mode, builds the UI, checks dependencies, and refreshes status.
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  // Register helper XPC service first (production-grade architecture)
  [self registerHelperIfNeeded];

  [self parseCLIArguments];
  if (self.cliMode) {
    for (NSString *action in self.cliActions) {
      if ([action isEqualToString:@"--check-token"]) {
        [self emitStatus:[self checkTokenStatus]];
      } else if ([action isEqualToString:@"--register-token"]) {
        [self emitStatus:[self registerPersistentTokenStatus]];
      } else if ([action isEqualToString:@"--initialize"]) {
        [self emitStatus:[self initializeTokenStatus]];
      }
    }
    [NSApp terminate:nil];
    return;
  }

  [self buildUI];
  [self checkDependencies];
  // Delay slightly to let window appear first
  dispatch_after(
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
      dispatch_get_main_queue(), ^{
        [self refreshStatus:nil];
      });
}

#pragma mark - Helper Service Management (Production-Grade, macOS 13+)

/// Registers the XPC helper service as a LaunchAgent using SMAppService (macOS
/// 13+). The helper service runs in the background and handles PKCS#11
/// operations that require entitlements not available to the sandboxed
/// CryptoTokenKit extension.
///
/// The helper is registered as an agent (not a daemon) so it runs in the user's
/// session and can access the smart card reader. User approval may be required
/// in System Settings.
- (void)registerHelperIfNeeded {
  // Modern SMAppService API (macOS 13+) - use agent for XPC services
  // Agents run in the user's login session and can access smart card readers
  SMAppService *service = [SMAppService
      agentServiceWithPlistName:@"com.andrei.rocei.connector.helper.plist"];

  os_log(OS_LOG_DEFAULT, "Connector: Helper agent service status: %ld",
         (long)service.status);

  // Check current registration status and register if needed
  switch (service.status) {
  case SMAppServiceStatusNotRegistered:
  case SMAppServiceStatusNotFound: {
    [self registerHelperService:service];
    break;
  }
  case SMAppServiceStatusEnabled:
    // Helper is already registered and enabled
    os_log(OS_LOG_DEFAULT,
           "Connector: Helper agent already registered and enabled");
    // Ensure helper is started by pinging it
    [self ensureHelperIsRunning];
    break;
  case SMAppServiceStatusRequiresApproval:
    os_log(OS_LOG_DEFAULT, "Connector: Helper agent requires user approval in "
                           "System Settings → General → Login Items");
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = @"Helper service needs approval";
    alert.informativeText =
        @"The helper service needs to be approved in System Settings → General "
        @"→ Login Items.\n\n"
         "Look for \"RO CEI Connector\" or \"ROCEIHelper\" and enable it.";
    [alert addButtonWithTitle:@"Open System Settings"];
    [alert addButtonWithTitle:@"Continue"];
    if ([alert runModal] == NSAlertFirstButtonReturn) {
      [[NSWorkspace sharedWorkspace]
          openURL:[NSURL URLWithString:@"x-apple.systempreferences:com.apple."
                                       @"LoginItems-Settings.extension"]];
    }
    break;
  }
}

/// Attempts to register the helper service with the system.
/// May require user approval in System Settings → General → Login Items.
///
/// @param service The SMAppService instance to register
- (void)registerHelperService:(SMAppService *)service {
  NSError *error = nil;
  BOOL registered = [service registerAndReturnError:&error];
  if (registered) {
    os_log(OS_LOG_DEFAULT, "Connector: Helper agent registered successfully");
    // Ensure helper starts after registration
    [self ensureHelperIsRunning];
  } else {
    os_log_error(OS_LOG_DEFAULT,
                 "Connector: Helper agent registration failed: %{public}@",
                 error);
    NSLog(@"ERROR: Failed to register helper agent: %@", error);
  }
}

/// Ensures the helper service is running by sending a ping via XPC.
/// XPC connections are lazy — launchd only starts the helper when an actual
/// message is sent, not when the connection object is created.  This method
/// sends a lightweight ping to trigger on-demand launch after registration.
- (void)ensureHelperIsRunning {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    os_log(OS_LOG_DEFAULT, "Connector: Ensuring helper is running (sending ping)...");
    
    NSXPCConnection *connection = [self helperConnection];
    if (!connection) {
      os_log_error(OS_LOG_DEFAULT, "Connector: Failed to create helper connection");
      return;
    }
    
    id<ROCEISigningServiceProtocol> proxy =
        [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
          os_log_error(OS_LOG_DEFAULT,
                       "Connector: Helper ping failed: %{public}@", error);
        }];
    
    // Actually send a message — this triggers launchd to start the helper
    [proxy pingWithReply:^(BOOL alive, NSString *version) {
      if (alive) {
        os_log(OS_LOG_DEFAULT,
               "Connector: Helper is running (version %{public}@)", version);
      }
    }];
  });
}

/// Creates and returns an XPC connection to the helper service.
/// The connection is cached and reused. If interrupted or invalidated, it will
/// be recreated on the next access.
///
/// The XPC interface is configured with secure coding to ensure type safety
/// when transferring certificate and key data between processes.
- (NSXPCConnection *)helperConnection {
  // Thread-safe singleton pattern for XPC connection
  @synchronized(self) {
    if (_helperConnection) {
      return _helperConnection; // Return cached connection
    }

    os_log(OS_LOG_DEFAULT,
           "Connector: Creating XPC connection to helper agent");

    // Create XPC connection to Mach service (registered by LaunchAgent)
    _helperConnection = [[NSXPCConnection alloc]
        initWithMachServiceName:@"com.andrei.rocei.connector.helper"
                        options:0];

    // Configure interface with secure coding for type safety
    // This ensures only expected class types are decoded, preventing object
    // substitution attacks
    NSXPCInterface *interface = [NSXPCInterface
        interfaceWithProtocol:@protocol(ROCEISigningServiceProtocol)];
    NSSet *certificateInfoClasses = [NSSet setWithArray:@[
      [ROCEICertificateInfo class], [NSArray class], [NSData class],
      [NSString class]
    ]];
    // Configure allowed classes for the reply parameter (array of
    // ROCEICertificateInfo)
    [interface setClasses:certificateInfoClasses
              forSelector:@selector(enumerateCertificatesWithSlot:reply:)
            argumentIndex:0
                  ofReply:YES];

    _helperConnection.remoteObjectInterface = interface;

    // Export progress protocol so the helper can send us step-by-step updates
    _helperConnection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(ROCEIProgressProtocol)];
    _helperConnection.exportedObject = self;

    // Handle connection lifecycle events
    __weak typeof(self) weakSelf = self;
    _helperConnection.interruptionHandler = ^{
      // Connection was interrupted (e.g., helper crashed) - will reconnect on
      // next use
      os_log(OS_LOG_DEFAULT,
             "Connector: XPC connection interrupted, will reconnect");
      @synchronized(weakSelf) {
        weakSelf.helperConnection = nil;
      }
    };
    _helperConnection.invalidationHandler = ^{
      // Connection was invalidated (e.g., helper terminated) - will reconnect
      // on next use
      os_log(OS_LOG_DEFAULT, "Connector: XPC connection invalidated");
      @synchronized(weakSelf) {
        weakSelf.helperConnection = nil;
      }
    };

    // Activate the connection
    [_helperConnection resume];
    os_log(OS_LOG_DEFAULT, "Connector: XPC connection established");

    return _helperConnection;
  } // @synchronized
}

/// Cleans up XPC connection on app termination.
- (void)applicationWillTerminate:(NSNotification *)notification {
  // Clean up XPC connection
  [self.helperConnection invalidate];
  self.helperConnection = nil;
}

/// Constructs the main application window with left control panel and right
/// status/results area. Creates all buttons, labels, and output views with
/// proper Auto Layout configurations.
- (void)buildUI {
  CGFloat margin = 16;
  CGFloat panelWidth = 220;
  CGFloat outputMinWidth = 560;
  CGFloat initialWidth = margin + panelWidth + margin + outputMinWidth + margin;
  CGFloat initialHeight = 780;

  NSRect frame = NSMakeRect(0, 0, initialWidth, initialHeight);
  self.window = [[NSWindow alloc]
      initWithContentRect:frame
                styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                           NSWindowStyleMaskMiniaturizable |
                           NSWindowStyleMaskResizable)
                  backing:NSBackingStoreBuffered
                    defer:NO];
  self.window.title = @"RO CEI Connector";

  NSView *content = self.window.contentView;
  CGFloat contentHeight = frame.size.height - margin * 2;

  // === LEFT: Action panel ===
  CGFloat pad = 14;
  CGFloat innerW = panelWidth - pad * 2;

  NSView *panel = [[NSView alloc]
      initWithFrame:NSMakeRect(margin, margin, panelWidth, contentHeight)];
  panel.autoresizingMask = NSViewHeightSizable;
  [content addSubview:panel];

  NSBox *panelBG =
      [[NSBox alloc] initWithFrame:NSMakeRect(0, 0, panelWidth, contentHeight)];
  panelBG.boxType = NSBoxCustom;
  panelBG.borderColor = [NSColor separatorColor];
  panelBG.borderWidth = 1;
  panelBG.fillColor = [[NSColor windowBackgroundColor]
      blendedColorWithFraction:0.3
                       ofColor:[NSColor controlBackgroundColor]];
  panelBG.cornerRadius = 8;
  panelBG.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  [panel addSubview:panelBG];

  CGFloat btnH = 32;
  CGFloat descH = 14;
  CGFloat gap = 8;
  __block CGFloat y = contentHeight - 12;
  NSUInteger topAnchor = NSViewMinYMargin;

  // --- Helpers ---
  void (^addSectionLabel)(NSString *) = ^(NSString *title) {
    y -= 20;
    NSTextField *lbl =
        [[NSTextField alloc] initWithFrame:NSMakeRect(pad, y, innerW, 14)];
    lbl.stringValue = [title uppercaseString];
    lbl.font = [NSFont systemFontOfSize:10 weight:NSFontWeightSemibold];
    lbl.textColor = [NSColor secondaryLabelColor];
    lbl.bezeled = NO;
    lbl.editable = NO;
    lbl.selectable = NO;
    lbl.backgroundColor = [NSColor clearColor];
    lbl.autoresizingMask = topAnchor;
    [panel addSubview:lbl];
    y -= 6;
  };

  NSButton * (^addButton)(NSString *, NSString *, SEL, NSView *) =
      ^NSButton *(NSString *title, NSString *desc, SEL action, NSView *parent) {
        NSButton *btn = [[NSButton alloc]
            initWithFrame:NSMakeRect(pad, y - btnH, innerW, btnH)];
        btn.title = title;
        btn.bezelStyle = NSBezelStyleRounded;
        btn.target = self;
        btn.action = action;
        btn.font = [NSFont systemFontOfSize:12];
        if (parent == panel)
          btn.autoresizingMask = topAnchor;
        [parent addSubview:btn];
        y -= btnH;
        if (desc.length > 0) {
          NSTextField *d = [[NSTextField alloc]
              initWithFrame:NSMakeRect(pad, y - descH, innerW, descH)];
          d.stringValue = desc;
          d.font = [NSFont systemFontOfSize:9];
          d.textColor = [NSColor tertiaryLabelColor];
          d.bezeled = NO;
          d.editable = NO;
          d.selectable = NO;
          d.backgroundColor = [NSColor clearColor];
          d.lineBreakMode = NSLineBreakByTruncatingTail;
          if (parent == panel)
            d.autoresizingMask = topAnchor;
          [parent addSubview:d];
          y -= descH;
        }
        y -= gap;
        return btn;
      };

  void (^addSeparator)(void) = ^{
    y -= 4;
    NSBox *sep = [[NSBox alloc] initWithFrame:NSMakeRect(pad, y, innerW, 1)];
    sep.boxType = NSBoxSeparator;
    sep.autoresizingMask = topAnchor;
    [panel addSubview:sep];
    y -= 4;
  };

  // ===== SETUP =====
  addSectionLabel(@"Setup");
  self.installCertsButton =
      addButton(@"Install CA Certificates", @"Trust MAI chain for Safari",
                @selector(installCACertificates:), panel);
  self.registerButton =
      addButton(@"Register Token", @"Register eID certificate with macOS",
                @selector(registerPersistentToken:), panel);
  addSeparator();

  // ===== STATUS =====
  addSectionLabel(@"Status");
  self.checkButton =
      addButton(@"Check Status", @"Verify card, tokens & identities",
                @selector(refreshStatus:), panel);
  addSeparator();

  // ===== ADVANCED (toggle + container) =====
  self.advancedToggle =
      [[NSButton alloc] initWithFrame:NSMakeRect(pad, y - btnH, innerW, btnH)];
  self.advancedToggle.title = @"Advanced \u25B6";
  self.advancedToggle.bezelStyle = NSBezelStyleRounded;
  self.advancedToggle.target = self;
  self.advancedToggle.action = @selector(toggleAdvanced:);
  self.advancedToggle.font = [NSFont systemFontOfSize:11];
  self.advancedToggle.autoresizingMask = topAnchor;
  [panel addSubview:self.advancedToggle];
  y -= btnH + 6;

  CGFloat advancedTop = y;
  CGFloat advBtnH = 28;
  CGFloat advDescH = 12;
  CGFloat advGap = 5;
  CGFloat advItemH = advBtnH + advDescH + advGap;
  CGFloat advancedHeight = 10 * advItemH + 4; // 10 buttons
  self.advancedContainer =
      [[NSView alloc] initWithFrame:NSMakeRect(0, advancedTop - advancedHeight,
                                               panelWidth, advancedHeight)];
  self.advancedContainer.hidden = YES;
  self.advancedVisible = NO;
  self.advancedContainer.autoresizingMask = topAnchor;
  [panel addSubview:self.advancedContainer];

  // Advanced buttons with descriptions (inside container)
  __block CGFloat ay = advancedHeight - 2;
  NSButton * (^addAdvButton)(NSString *, NSString *, SEL) =
      ^NSButton *(NSString *title, NSString *desc, SEL action) {
        NSButton *btn = [[NSButton alloc]
            initWithFrame:NSMakeRect(pad, ay - advBtnH, innerW, advBtnH)];
        btn.title = title;
        btn.bezelStyle = NSBezelStyleRounded;
        btn.target = self;
        btn.action = action;
        btn.font = [NSFont systemFontOfSize:11];
        [self.advancedContainer addSubview:btn];
        ay -= advBtnH;
        NSTextField *d = [[NSTextField alloc]
            initWithFrame:NSMakeRect(pad, ay - advDescH, innerW, advDescH)];
        d.stringValue = desc;
        d.font = [NSFont systemFontOfSize:8.5];
        d.textColor = [NSColor tertiaryLabelColor];
        d.bezeled = NO;
        d.editable = NO;
        d.selectable = NO;
        d.backgroundColor = [NSColor clearColor];
        [self.advancedContainer addSubview:d];
        ay -= advDescH + advGap;
        return btn;
      };

  self.setupButton = addAdvButton(@"Test Sign", @"Verify PIN and signing work",
                                  @selector(initializeToken:));
  self.resetCtkdButton =
      addAdvButton(@"Reset CTK Daemon", @"Restart CryptoTokenKit services",
                   @selector(resetCTKDaemon:));
  self.verifyButton =
      addAdvButton(@"Verify Installation", @"Check extension, helper, old data",
                   @selector(verifyInstallation:));
  self.deregisterTokenButton =
      addAdvButton(@"Deregister Token", @"Remove registered eID identity",
                   @selector(deregisterToken:));
  self.unregisterButton =
      addAdvButton(@"Unregister Extension", @"Remove extension from PluginKit",
                   @selector(unregisterExtension:));
  self.registerExtButton =
      addAdvButton(@"Register Extension", @"Add extension to PluginKit",
                   @selector(registerExtension:));
  self.extensionInfoButton =
      addAdvButton(@"Extension Info", @"Show bundle and driver details",
                   @selector(showExtensionInfo:));
  self.killPkcs11Button =
      addAdvButton(@"Kill pkcs11-tool", @"Force kill all pkcs11-tool processes",
                   @selector(killPkcs11Processes:));
  self.resetPKCS11Button = addAdvButton(
      @"Reset PKCS#11", @"Close sessions, kill processes, clear cached state",
      @selector(resetPKCS11:));
  self.uninstallButton = addAdvButton(
      @"Uninstall", @"Remove everything and delete the app",
      @selector(uninstallApp:));
  self.uninstallButton.contentTintColor = [NSColor systemRedColor];

  // === RIGHT: Output area ===
  CGFloat outputX = margin + panelWidth + margin;
  CGFloat outputW = outputMinWidth;
  CGFloat detailH = 200;
  CGFloat resultsH = 68; // Minimal initial height (will grow with rows)

  // Container for results + detail
  self.outputContainer = [[NSView alloc]
      initWithFrame:NSMakeRect(outputX, margin, outputW, contentHeight)];
  self.outputContainer.autoresizingMask =
      NSViewWidthSizable | NSViewHeightSizable;
  [content addSubview:self.outputContainer];

  // Results view - fixed size container for rows (positioned at top)
  NSBox *resultsBox = [[NSBox alloc]
      initWithFrame:NSMakeRect(0, contentHeight - resultsH, outputW, resultsH)];
  resultsBox.boxType = NSBoxCustom;
  resultsBox.borderWidth = 1;
  resultsBox.borderColor = [NSColor separatorColor];
  resultsBox.fillColor = [NSColor controlBackgroundColor];
  resultsBox.cornerRadius = 8;
  resultsBox.autoresizingMask =
      NSViewWidthSizable | NSViewMinYMargin; // fixed at top

  // Use flipped view so rows stack from top-down
  NSFlippedClipView *flippedClip = [[NSFlippedClipView alloc]
      initWithFrame:NSMakeRect(0, 0, outputW, resultsH)];
  NSView *resultsView =
      [[NSView alloc] initWithFrame:NSMakeRect(0, 0, outputW, resultsH)];
  [flippedClip addSubview:resultsView];
  resultsBox.contentView = flippedClip;

  // Store results view and box for row management
  self.resultsView = resultsView;
  self.resultsBox = resultsBox;

  [self.outputContainer addSubview:resultsBox];

  // Detail text view (bottom, initially hidden) - scrollable text view in a box
  NSBox *detailBox =
      [[NSBox alloc] initWithFrame:NSMakeRect(0, 0, outputW, detailH)];
  detailBox.boxType = NSBoxCustom;
  detailBox.borderWidth = 1;
  detailBox.borderColor = [NSColor separatorColor];
  detailBox.fillColor = [NSColor textBackgroundColor];
  detailBox.cornerRadius = 8;
  detailBox.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  detailBox.hidden = YES;
  detailBox.titlePosition = NSNoTitle;

  // Scroll view fills the content view of the box
  NSScrollView *detailScrollView =
      [[NSScrollView alloc] initWithFrame:detailBox.contentView.bounds];
  detailScrollView.hasVerticalScroller = YES;
  detailScrollView.hasHorizontalScroller = NO;
  detailScrollView.borderType = NSNoBorder;
  detailScrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

  // Text view sized to fit in the scroll view
  NSSize contentSize = [detailScrollView contentSize];
  self.detailView = [[NSTextView alloc]
      initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)];
  self.detailView.minSize = NSMakeSize(0, contentSize.height);
  self.detailView.maxSize = NSMakeSize(FLT_MAX, FLT_MAX);
  self.detailView.verticallyResizable = YES;
  self.detailView.horizontallyResizable = NO;
  self.detailView.autoresizingMask = NSViewWidthSizable;
  self.detailView.textContainer.containerSize =
      NSMakeSize(contentSize.width, FLT_MAX);
  self.detailView.textContainer.widthTracksTextView = YES;
  self.detailView.editable = NO;
  self.detailView.selectable = YES;
  self.detailView.font =
      [NSFont monospacedSystemFontOfSize:10 weight:NSFontWeightRegular];
  self.detailView.textContainerInset = NSMakeSize(8, 8);
  detailScrollView.documentView = self.detailView;

  [detailBox.contentView addSubview:detailScrollView];

  self.detailBox = detailBox;
  [self.outputContainer addSubview:detailBox];

  self.statusRows = [NSMutableArray array];

  self.window.minSize =
      NSMakeSize(margin + panelWidth + margin + 300 + margin, 450);
  [self.window center];
  [self.window makeKeyAndOrderFront:nil];
}

/// Toggles the visibility of the advanced options panel.
/// Advanced options include: Test Sign, Reset ctkd, Verify Installation,
/// Deregister Token, Extension Info, etc.
///
/// @param sender The control that triggered the action
- (IBAction)toggleAdvanced:(id)sender {
  self.advancedVisible = !self.advancedVisible;
  self.advancedToggle.title =
      self.advancedVisible ? @"Advanced \u25BC" : @"Advanced \u25B6";
  self.advancedContainer.hidden = !self.advancedVisible;
}

#pragma mark - GUI Row Helpers

/// Remove all status rows and hide the detail view. Runs synchronously on main
/// thread.
- (void)clearResults {
  dispatch_block_t work = ^{
    for (ROCEIStatusRow *row in self.statusRows) {
      [row.rowView removeFromSuperview];
    }
    [self.statusRows removeAllObjects];
    [self hideDetailView];
  };
  if ([NSThread isMainThread]) {
    work();
  } else {
    dispatch_sync(dispatch_get_main_queue(), work);
  }
}

/// Add a new status row. Returns the row index. Safe to call from any thread.
/// @param title Row title
/// @param waiting If YES, shows "Waiting…" with no spinner; if NO, shows
/// "Running…" with spinner
- (NSUInteger)addRowWithTitle:(NSString *)title waiting:(BOOL)waiting {
  __block NSUInteger idx;
  dispatch_block_t work = ^{
    ROCEIStatusRow *row = [[ROCEIStatusRow alloc] init];
    CGFloat rowH = 48;
    CGFloat iconSize = 18;
    CGFloat pad = 10;
    NSView *resultsView = self.resultsView;
    CGFloat w = resultsView.frame.size.width - 20;

    // Calculate Y position from TOP (flipped coordinate system)
    CGFloat topPadding = 10;
    CGFloat currentHeight = topPadding;
    for (ROCEIStatusRow *existingRow in self.statusRows) {
      currentHeight += existingRow.rowView.frame.size.height;
    }
    CGFloat y = currentHeight;

    row.rowView = [[NSView alloc] initWithFrame:NSMakeRect(10, y, w, rowH)];
    row.rowView.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;

    // Alternating row background
    if (self.statusRows.count % 2 == 1) {
      NSBox *bg = [[NSBox alloc] initWithFrame:NSMakeRect(0, 0, w, rowH)];
      bg.boxType = NSBoxCustom;
      bg.borderWidth = 0;
      bg.fillColor = [[NSColor controlBackgroundColor]
          blendedColorWithFraction:0.3
                           ofColor:[NSColor separatorColor]];
      bg.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
      [row.rowView addSubview:bg];
    }

    // Spinner (visible while running)
    row.spinner = [[NSProgressIndicator alloc]
        initWithFrame:NSMakeRect(pad, (rowH - iconSize) / 2, iconSize,
                                 iconSize)];
    row.spinner.style = NSProgressIndicatorStyleSpinning;
    row.spinner.controlSize = NSControlSizeSmall;
    row.spinner.displayedWhenStopped = NO;
    if (!waiting) {
      [row.spinner startAnimation:nil];
    } else {
      row.spinner.hidden = YES;
    }
    [row.rowView addSubview:row.spinner];

    // Icon (hidden initially, shown on completion)
    row.iconView = [[NSImageView alloc]
        initWithFrame:NSMakeRect(pad, (rowH - iconSize) / 2, iconSize,
                                 iconSize)];
    row.iconView.imageScaling = NSImageScaleProportionallyUpOrDown;
    row.iconView.hidden = YES;
    [row.rowView addSubview:row.iconView];

    CGFloat textX = pad + iconSize + 8;
    CGFloat btnW = 60;
    CGFloat textW = w - textX - btnW - pad;

    // Title
    row.titleLabel = [[NSTextField alloc]
        initWithFrame:NSMakeRect(textX, rowH - 8 - 16, textW, 16)];
    row.titleLabel.stringValue = title;
    row.titleLabel.font = [NSFont systemFontOfSize:12
                                            weight:NSFontWeightMedium];
    row.titleLabel.textColor = [NSColor labelColor];
    row.titleLabel.bezeled = NO;
    row.titleLabel.editable = NO;
    row.titleLabel.selectable = NO;
    row.titleLabel.backgroundColor = [NSColor clearColor];
    row.titleLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    [row.rowView addSubview:row.titleLabel];

    // Summary (below title, secondary text)
    row.summaryLabel =
        [[NSTextField alloc] initWithFrame:NSMakeRect(textX, 6, textW, 14)];
    row.summaryLabel.stringValue = waiting ? @"Waiting…" : @"Running…";
    row.summaryLabel.font = [NSFont systemFontOfSize:10.5];
    row.summaryLabel.textColor =
        waiting ? [NSColor tertiaryLabelColor] : [NSColor secondaryLabelColor];
    row.summaryLabel.bezeled = NO;
    row.summaryLabel.editable = NO;
    row.summaryLabel.selectable = NO;
    row.summaryLabel.backgroundColor = [NSColor clearColor];
    row.summaryLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    [row.rowView addSubview:row.summaryLabel];

    // Details button (hidden initially)
    row.detailsButton = [[NSButton alloc]
        initWithFrame:NSMakeRect(w - btnW - pad, (rowH - 22) / 2, btnW, 22)];
    row.detailsButton.title = @"Details";
    row.detailsButton.bezelStyle = NSBezelStyleInline;
    row.detailsButton.font = [NSFont systemFontOfSize:10];
    row.detailsButton.target = self;
    row.detailsButton.action = @selector(showRowDetails:);
    row.detailsButton.hidden = YES;
    row.detailsButton.autoresizingMask = NSViewMinXMargin;
    [row.rowView addSubview:row.detailsButton];

    [resultsView addSubview:row.rowView];
    [self.statusRows addObject:row];
    idx = self.statusRows.count - 1;
  };

  if ([NSThread isMainThread]) {
    work();
  } else {
    dispatch_sync(dispatch_get_main_queue(), work);
  }

  // Update box height to fit all rows
  [self updateResultsBoxHeight];

  return idx;
}

/// Convenience method: add a row that starts immediately (not waiting).
- (NSUInteger)addRowWithTitle:(NSString *)title {
  return [self addRowWithTitle:title waiting:NO];
}

/// Update the results box height to fit all status rows.
- (void)updateResultsBoxHeight {
  dispatch_block_t work = ^{
    if (self.statusRows.count == 0)
      return;

    NSBox *resultsBox = self.resultsBox;
    CGFloat rowH = 48;
    CGFloat topPadding = 10;
    CGFloat bottomPadding = 10;
    CGFloat newHeight =
        topPadding + (self.statusRows.count * rowH) + bottomPadding;

    // Get current frame and update height
    NSRect currentFrame = resultsBox.frame;
    CGFloat contentHeight = self.outputContainer.frame.size.height;
    NSRect newFrame =
        NSMakeRect(currentFrame.origin.x, contentHeight - newHeight,
                   currentFrame.size.width, newHeight);
    resultsBox.frame = newFrame;

    // Update the flipped clip view and content view size as well
    NSFlippedClipView *flippedClip =
        (NSFlippedClipView *)resultsBox.contentView;
    flippedClip.frame = NSMakeRect(0, 0, currentFrame.size.width, newHeight);
    NSView *resultsView = flippedClip.subviews.firstObject;
    if (resultsView) {
      resultsView.frame = NSMakeRect(0, 0, currentFrame.size.width, newHeight);
    }
  };

  if ([NSThread isMainThread]) {
    work();
  } else {
    dispatch_async(dispatch_get_main_queue(), work);
  }
}

/// Start a waiting row (transition from "Waiting..." to "Running..."). Safe to
/// call from any thread.
/// Transition a waiting row to the running state (show spinner).
///
/// @param index Row index to start
- (void)startRow:(NSUInteger)index {
  dispatch_block_t work = ^{
    if (index >= self.statusRows.count)
      return;
    ROCEIStatusRow *row = self.statusRows[index];
    row.summaryLabel.stringValue = @"Running…";
    row.summaryLabel.textColor = [NSColor secondaryLabelColor];
    row.spinner.hidden = NO;
    [row.spinner startAnimation:nil];
  };
  if (![NSThread isMainThread]) {
    dispatch_async(dispatch_get_main_queue(), work);
  } else {
    work();
  }
}

/// Complete a row: stop spinner, show icon (checkmark or X), set summary,
/// optionally store raw output.
- (void)completeRow:(NSUInteger)index
            success:(BOOL)success
            summary:(NSString *)summary
             detail:(NSString *)rawOutput {
  dispatch_block_t work = ^{
    if (index >= self.statusRows.count)
      return;
    ROCEIStatusRow *row = self.statusRows[index];

    [row.spinner stopAnimation:nil];
    row.spinner.hidden = YES;

    NSImage *icon;
    if (success) {
      icon = [NSImage imageWithSystemSymbolName:@"checkmark.circle.fill"
                       accessibilityDescription:@"Success"];
      row.iconView.contentTintColor = [NSColor systemGreenColor];
    } else {
      icon = [NSImage imageWithSystemSymbolName:@"xmark.circle.fill"
                       accessibilityDescription:@"Error"];
      row.iconView.contentTintColor = [NSColor systemRedColor];
    }
    row.iconView.image = icon;
    row.iconView.hidden = NO;

    row.summaryLabel.stringValue = summary ?: @"";
    row.summaryLabel.textColor =
        success ? [NSColor secondaryLabelColor] : [NSColor systemRedColor];

    if (rawOutput.length > 0) {
      row.rawOutput = rawOutput;
      row.detailsButton.hidden = NO;
      row.detailsButton.tag = (NSInteger)index;
    }
  };

  if ([NSThread isMainThread]) {
    work();
  } else {
    dispatch_async(dispatch_get_main_queue(), work);
  }
}

/// Complete a row with a warning state (yellow icon).
- (void)completeRow:(NSUInteger)index
            warning:(NSString *)summary
             detail:(NSString *)rawOutput {
  dispatch_block_t work = ^{
    if (index >= self.statusRows.count)
      return;
    ROCEIStatusRow *row = self.statusRows[index];

    [row.spinner stopAnimation:nil];
    row.spinner.hidden = YES;

    NSImage *icon =
        [NSImage imageWithSystemSymbolName:@"exclamationmark.triangle.fill"
                  accessibilityDescription:@"Warning"];
    row.iconView.image = icon;
    row.iconView.contentTintColor = [NSColor systemYellowColor];
    row.iconView.hidden = NO;

    row.summaryLabel.stringValue = summary ?: @"";
    row.summaryLabel.textColor = [NSColor systemOrangeColor];

    if (rawOutput.length > 0) {
      row.rawOutput = rawOutput;
      row.detailsButton.hidden = NO;
      row.detailsButton.tag = (NSInteger)index;
    }
  };
  if ([NSThread isMainThread])
    work();
  else
    dispatch_async(dispatch_get_main_queue(), work);
}

/// "Details" button action — show raw output in the detail text view.
- (IBAction)showRowDetails:(id)sender {
  NSInteger idx = [(NSButton *)sender tag];
  if (idx < 0 || idx >= (NSInteger)self.statusRows.count)
    return;
  ROCEIStatusRow *row = self.statusRows[idx];
  [self showDetailText:row.rawOutput ?: @"(no output)"];
}

/// Show the detail text view with the given text (appears below fixed-size
/// results box).
- (void)showDetailText:(NSString *)text {
  CGFloat outputGap = 12;
  CGFloat bottomMargin = 12; // margin from bottom of container
  CGFloat w = self.outputContainer.frame.size.width;
  NSBox *detailBox = self.detailBox;
  NSBox *resultsBox = self.resultsBox;

  self.detailView.string = text;
  detailBox.hidden = NO;

  // Position detail box just below the results box and extend to bottom
  CGFloat resultsY = resultsBox.frame.origin.y;
  CGFloat detailY = bottomMargin; // start from bottom margin
  CGFloat detailH = resultsY - outputGap - bottomMargin; // fill available space

  // Ensure minimum height
  if (detailH < 100)
    detailH = 100;

  NSRect detailFrame = NSMakeRect(0, detailY, w, detailH);
  detailBox.frame = detailFrame;
  detailBox.autoresizingMask =
      NSViewWidthSizable | NSViewHeightSizable; // resizes with window
}

/// Hide the detail text view.
- (void)hideDetailView {
  self.detailBox.hidden = YES;
  self.detailView.string = @"";
}

/// Runs an external command synchronously with a timeout.
/// Captures combined stdout/stderr output and formats a summary including
/// the exit code or termination reason.
///
/// @param launchPath Absolute path to the executable
/// @param arguments Command arguments
/// @param timeoutSeconds Maximum execution time before the task is killed
/// @return Formatted string with the command, exit status, and output
- (NSString *)runCommand:(NSString *)launchPath
               arguments:(NSArray<NSString *> *)arguments
          timeoutSeconds:(NSTimeInterval)timeoutSeconds {
  NSTask *task = [[NSTask alloc] init];
  task.launchPath = launchPath;
  task.arguments = arguments;

  NSPipe *inputPipe = [NSPipe pipe];
  NSPipe *pipe = [NSPipe pipe];
  task.standardInput = inputPipe;
  task.standardOutput = pipe;
  task.standardError = pipe;

  // Build the full command string for error reporting (quote args with spaces)
  NSMutableString *fullCommand = [NSMutableString stringWithString:launchPath];
  for (NSString *arg in arguments) {
    [fullCommand appendString:@" "];
    if ([arg containsString:@" "]) {
      [fullCommand appendFormat:@"\"%@\"", arg];
    } else {
      [fullCommand appendString:arg];
    }
  }

  @try {
    [task launch];
  } @catch (NSException *exception) {
    return [NSString stringWithFormat:@"$ %@\nFailed to launch: %@\n",
                                      fullCommand, exception.reason];
  }

  // Close stdin so tools don't hang waiting for terminal input.
  [[inputPipe fileHandleForWriting] closeFile];

  __block NSData *data = nil;
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    data = [[pipe fileHandleForReading] readDataToEndOfFile];
    dispatch_semaphore_signal(sem);
  });

  dispatch_time_t timeout = dispatch_time(
      DISPATCH_TIME_NOW, (int64_t)(timeoutSeconds * NSEC_PER_SEC));
  if (dispatch_semaphore_wait(sem, timeout) != 0) {
    [task terminate];
    [[pipe fileHandleForReading] closeFile];
    // Give the reader a moment to unwind. This ensures the background thread
    // completes and signals the semaphore before the semaphore is deallocated.
    dispatch_semaphore_wait(
        sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)));
    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"$ %@\nTIMED OUT after %.0fs\n", fullCommand,
                         timeoutSeconds];
    NSString *partial =
        data
            ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
            : nil;
    if (partial.length > 0) {
      [result appendFormat:@"--- partial output ---\n%@\n", partial];
    }
    return result;
  }

  [task waitUntilExit];
  NSString *out =
      [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
  int exitCode = task.terminationStatus;

  // Build result with command header
  NSMutableString *result = [NSMutableString string];
  [result appendFormat:@"$ %@\n", fullCommand];

  if (exitCode != 0) {
    [result appendFormat:@"ERROR (exit %d)\n", exitCode];
    if (out.length > 0) {
      [result appendString:out];
      if (![out hasSuffix:@"\n"])
        [result appendString:@"\n"];
    }
    return result;
  }

  if (out.length == 0) {
    [result appendString:@"(no output)\n"];
    return result;
  }

  [result appendString:out];
  if (![out hasSuffix:@"\n"])
    [result appendString:@"\n"];
  return result;
}

/// Convenience wrapper: runs a command with the default 15-second timeout.
- (NSString *)runCommand:(NSString *)launchPath
               arguments:(NSArray<NSString *> *)arguments {
  return [self runCommand:launchPath arguments:arguments timeoutSeconds:15];
}

/// Returns the best available path to the PKCS#11 library using the shared
/// search order defined in PKCS11.h (appex Resources → IDplugManager).
- (NSString *)pkcs11ModulePath {
  return PKCS11FindLibraryPath();
}

/// Compute SHA-512 hash of a file. Uses the shared PKCS11ComputeSHA512()
/// implementation from PKCS11.h.
- (NSString *)sha512HashOfFileAtPath:(NSString *)path {
  return PKCS11ComputeSHA512(path);
}

/// Checks for required dependencies (PKCS#11 library, pkcs11-tool) and
/// validates PKCS#11 library integrity via SHA-512 hash comparison.
/// Displays warnings if dependencies are missing or library version is unknown.
- (void)checkDependencies {
  NSFileManager *fm = [NSFileManager defaultManager];

  // 1. PKCS#11 library (critical — everything depends on this)

  // First verify IDplugManager library version if it exists
  // Hash list is defined in PKCS11.h (single source of truth shared with
  // PKCS11.m's supply-chain gate)
  NSString *idplugSourcePath = PKCS11IDplugManagerLibraryPath();
  if ([fm fileExistsAtPath:idplugSourcePath]) {
    NSString *actualHash = [self sha512HashOfFileAtPath:idplugSourcePath];
    NSArray<NSString *> *knownHashes = PKCS11KnownGoodLibraryHashes();

    if (actualHash && ![knownHashes containsObject:actualHash]) {
      os_log(OS_LOG_DEFAULT,
             "Connector: IDplugManager PKCS#11 library hash mismatch - "
             "got %{public}@",
             actualHash);

      NSString *expectedHashList =
          [knownHashes componentsJoinedByString:@"\n  "];
      NSAlert *alert = [[NSAlert alloc] init];
      alert.alertStyle = NSAlertStyleWarning;
      alert.messageText = @"Unsupported PKCS#11 library version";
      alert.informativeText = [NSString
          stringWithFormat:
              @"The IDplugManager PKCS#11 library version may be "
              @"unsupported.\n\n"
              @"Expected (known-good IDplugManager versions):\n  %@\n\n"
              @"Actual hash:\n  %@\n\n"
              @"The app may not work correctly. Continue at your own risk.",
              expectedHashList, actualHash];
      [alert addButtonWithTitle:@"Continue Anyway"];
      [alert addButtonWithTitle:@"Quit"];
      NSModalResponse response = [alert runModal];
      if (response == NSAlertSecondButtonReturn) {
        [NSApp terminate:nil];
        return;
      }
    } else if (actualHash) {
      os_log(
          OS_LOG_DEFAULT,
          "Connector: IDplugManager PKCS#11 library version verified (4.5.0)");
    }
  }

  // Check if the library is available from any location (bundle or
  // IDplugManager)
  NSString *modulePath = [self pkcs11ModulePath];
  if (!modulePath) {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleCritical;
    alert.messageText = @"IDplugManager is required";
    alert.informativeText =
        @"The IDEMIA PKCS#11 library (libidplug-pkcs11.dylib) was not "
        @"found.\n\n"
         "This library is provided by IDplugManager.app and is required for "
         "all smart card operations.\n\n"
         "Install IDplugManager first, then relaunch this app.";
    [alert addButtonWithTitle:@"Quit"];
    [alert addButtonWithTitle:@"Continue Anyway"];
    NSModalResponse response = [alert runModal];
    if (response == NSAlertFirstButtonReturn) {
      [NSApp terminate:nil];
      return;
    }
  }

  // 2. OpenSC / pkcs11-tool (optional — diagnostics only)
  if ([self pkcs11ToolPath] == nil) {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = @"pkcs11-tool not found";
    alert.informativeText =
        @"OpenSC is not installed. Smart card diagnostics (PKCS#11 slot "
        @"listing, public key enumeration) will be unavailable.\n\n"
         "Install OpenSC "
         "from:\nhttps://github.com/OpenSC/OpenSC/releases/latest";
    [alert addButtonWithTitle:@"Continue"];
    [alert addButtonWithTitle:@"Open Download Page"];
    NSModalResponse response = [alert runModal];
    if (response == NSAlertSecondButtonReturn) {
      [[NSWorkspace sharedWorkspace]
          openURL:[NSURL
                      URLWithString:
                          @"https://github.com/OpenSC/OpenSC/releases/latest"]];
    }
  }
}

/// Installs the Romanian eID MAI root and sub CA certificates into the user's
/// login keychain and marks them as trusted. This is required for Safari
/// to offer the eID certificate during TLS client authentication — Safari
/// requires a complete, trusted certificate chain. Uses the `security` CLI tool
/// which properly handles keychain authentication.
- (IBAction)installCACertificates:(id)sender {
  [self clearResults];
  self.installCertsButton.enabled = NO;

  // Check if already installed by looking for trust settings on the root CA
  NSString *rootPath =
      [[NSBundle mainBundle] pathForResource:@"ro_cei_mai_root-ca"
                                      ofType:@"cer"];
  if (!rootPath) {
    NSUInteger r = [self addRowWithTitle:@"Root CA Certificate" waiting:NO];
    [self completeRow:r
              success:NO
              summary:@"Certificate not found in app bundle"
               detail:nil];
    self.installCertsButton.enabled = YES;
    return;
  }

  NSData *rootData = [NSData dataWithContentsOfFile:rootPath];
  SecCertificateRef rootCert =
      rootData
          ? SecCertificateCreateWithData(NULL, (__bridge CFDataRef)rootData)
          : NULL;
  if (rootCert) {
    CFArrayRef existingSettings = NULL;
    OSStatus sts = SecTrustSettingsCopyTrustSettings(
        rootCert, kSecTrustSettingsDomainUser, &existingSettings);
    CFRelease(rootCert);
    if (sts == errSecSuccess && existingSettings != NULL) {
      CFRelease(existingSettings);
      NSUInteger r = [self addRowWithTitle:@"CA Certificates" waiting:NO];
      [self completeRow:r
                success:YES
                summary:@"Already trusted in your keychain"
                 detail:nil];
      self.installCertsButton.enabled = YES;
      return;
    }
  }

  NSString *keychainPath = [NSHomeDirectory()
      stringByAppendingPathComponent:@"Library/Keychains/login.keychain-db"];

  // Row 1: Sub-CA
  NSUInteger subRow = [self addRowWithTitle:@"Install Sub-CA" waiting:NO];
  // Row 2: Root CA (waits for Sub-CA)
  NSUInteger rootRow = [self addRowWithTitle:@"Trust Root CA" waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // Step 1: Add sub-CA
    NSString *subCAPath =
        [[NSBundle mainBundle] pathForResource:@"ro_cei_mai_sub-ca"
                                        ofType:@"cer"];
    if (subCAPath) {
      NSTask *addTask = [[NSTask alloc] init];
      addTask.launchPath = @"/usr/bin/security";
      addTask.arguments =
          @[ @"add-certificates", @"-k", keychainPath, subCAPath ];
      NSPipe *addPipe = [NSPipe pipe];
      addTask.standardError = addPipe;
      addTask.standardOutput = addPipe;
      NSError *err = nil;
      [addTask launchAndReturnError:&err];
      if (!err) {
        [addTask waitUntilExit];
        NSData *d = [addPipe.fileHandleForReading readDataToEndOfFile];
        NSString *raw = [[NSString alloc] initWithData:d
                                              encoding:NSUTF8StringEncoding]
                            ?: @"";
        if (addTask.terminationStatus == 0) {
          [self completeRow:subRow
                    success:YES
                    summary:@"Added to login keychain"
                     detail:nil];
        } else {
          [self completeRow:subRow
                    success:NO
                    summary:@"Failed to add"
                     detail:raw];
        }
      } else {
        [self completeRow:subRow
                  success:NO
                  summary:@"Could not run security tool"
                   detail:err.localizedDescription];
      }
    } else {
      [self completeRow:subRow
                success:NO
                summary:@"Sub-CA not found in bundle"
                 detail:nil];
    }

    // Step 2: Trust root CA (may trigger macOS password prompt)
    [self startRow:rootRow];
    NSString *rootCAPath =
        [[NSBundle mainBundle] pathForResource:@"ro_cei_mai_root-ca"
                                        ofType:@"cer"];
    if (rootCAPath) {
      NSTask *trustTask = [[NSTask alloc] init];
      trustTask.launchPath = @"/usr/bin/security";
      trustTask.arguments = @[
        @"add-trusted-cert", @"-r", @"trustRoot", @"-k", keychainPath,
        rootCAPath
      ];
      NSPipe *trustPipe = [NSPipe pipe];
      trustTask.standardError = trustPipe;
      trustTask.standardOutput = trustPipe;
      NSError *err = nil;
      [trustTask launchAndReturnError:&err];
      if (!err) {
        [trustTask waitUntilExit];
        NSData *d = [trustPipe.fileHandleForReading readDataToEndOfFile];
        NSString *raw = [[NSString alloc] initWithData:d
                                              encoding:NSUTF8StringEncoding]
                            ?: @"";
        if (trustTask.terminationStatus == 0) {
          [self completeRow:rootRow
                    success:YES
                    summary:@"Installed and trusted"
                     detail:nil];
        } else {
          [self completeRow:rootRow
                    success:NO
                    summary:@"Failed — see details"
                     detail:raw];
        }
      } else {
        [self completeRow:rootRow
                  success:NO
                  summary:@"Could not run security tool"
                   detail:err.localizedDescription];
      }
    } else {
      [self completeRow:rootRow
                success:NO
                summary:@"Root CA not found in bundle"
                 detail:nil];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      self.installCertsButton.enabled = YES;
    });
  });
}

/// Returns the path to the pkcs11-tool executable (from OpenSC package).
/// Checks /usr/local/bin first (standard PATH), then /Library/OpenSC/bin.
///
/// @return Path to pkcs11-tool, or nil if OpenSC is not installed
- (NSString *)pkcs11ToolPath {
  // Prefer /usr/local/bin (standard PATH location, often a symlink to OpenSC)
  NSFileManager *fm = [NSFileManager defaultManager];
  if ([fm isExecutableFileAtPath:@"/usr/local/bin/pkcs11-tool"]) {
    return @"/usr/local/bin/pkcs11-tool";
  }
  if ([fm isExecutableFileAtPath:@"/Library/OpenSC/bin/pkcs11-tool"]) {
    return @"/Library/OpenSC/bin/pkcs11-tool";
  }
  return nil;
}

// Not needed - registration works without PIN prompt
//- (NSString *)promptForOptionalPIN {
//    NSAlert *alert = [[NSAlert alloc] init];
//    alert.messageText = @"Optional PIN";
//    alert.informativeText = @"Enter PIN to allow pkcs11-tool to list public
//    keys (optional). Leave empty to skip."; [alert
//    addButtonWithTitle:@"Continue"]; [alert addButtonWithTitle:@"Skip"];
//
//    NSSecureTextField *pinField = [[NSSecureTextField alloc]
//    initWithFrame:NSMakeRect(0, 0, 240, 24)]; alert.accessoryView = pinField;
//    [alert.window makeFirstResponder:pinField];
//
//    NSModalResponse response = [alert runModal];
//    if (response == NSAlertFirstButtonReturn) {
//        return pinField.stringValue ?: @"";
//    }
//    return @"";
//}

/// Parses command-line arguments for CLI mode operation.
/// Recognizes flags: --check-token, --register-token, --initialize, --slot=0xN.
/// If any recognized flags are found, enables CLI mode which skips GUI setup
/// and exits after running requested operations.
///
/// SECURITY: --pin argument is explicitly rejected to prevent PIN exposure
/// in process listings, shell history, and system logs.
- (void)parseCLIArguments {
  NSArray<NSString *> *args = [NSProcessInfo processInfo].arguments ?: @[];
  NSMutableArray<NSString *> *actions = [NSMutableArray array];
  for (NSInteger i = 1; i < (NSInteger)args.count; i++) {
    NSString *arg = args[i];
    if ([arg isEqualToString:@"--check-token"] ||
        [arg isEqualToString:@"--register-token"] ||
        [arg isEqualToString:@"--initialize"]) {
      [actions addObject:arg];
      continue;
    }
    if ([arg isEqualToString:@"--slot"] && (i + 1) < (NSInteger)args.count) {
      self.cliSlot = args[i + 1];
      i++;
      continue;
    }
    // SECURITY: --pin argument is explicitly NOT supported.
    // PINs on command line would be visible in process listings (ps, top),
    // shell history, system logs, and readable by any process. Use GUI mode
    // for PIN-protected operations.
    if ([arg isEqualToString:@"--pin"]) {
      fprintf(stderr, "ERROR: --pin argument not supported for security reasons.\n");
      fprintf(stderr, "PINs on command line are visible in process listings, "
                      "shell history, and system logs.\n");
      fprintf(stderr, "Use the GUI application for PIN-protected operations.\n");
      [NSApp terminate:nil];
    }
  }
  self.cliActions = actions;
  self.cliMode = (actions.count > 0);
}

/// Outputs status text to stdout for CLI mode.
///
/// @param status The status text to print
- (void)emitStatus:(NSString *)status {
  if (self.cliMode && status.length > 0) {
    fprintf(stdout, "%s", status.UTF8String);
    fflush(stdout);
  }
}

/// Returns the check-status report for CLI mode.
/// Queries: sc_auth identities, CryptoTokenKit token list, PKCS#11 slots,
/// and public keys.
///
/// @return Multi-line status report string
- (NSString *)checkTokenStatus {
  // Synchronous version for CLI mode
  NSMutableString *status = [NSMutableString string];
  NSString *modulePath = [self pkcs11ModulePath];
  NSString *pkcs11Tool = [self pkcs11ToolPath];

  [status appendString:@"CHECK STATUS\n\n"];
  [status appendString:@"  Smart Card Identities\n"];
  [status appendFormat:@"  > %@\n", [self runCommand:@"/usr/sbin/sc_auth"
                                           arguments:@[ @"identities" ]]];

  [status appendString:@"  CryptoTokenKit Tokens\n"];
  NSArray<NSString *> *allTokenIDs = [self allTokenIDs];
  if (allTokenIDs.count == 0) {
    [status appendString:@"  > No tokens registered\n"];
  } else {
    NSString *classID = @"com.andrei.rocei.connector.extension";
    for (NSString *tokenID in allTokenIDs) {
      NSString *marker = [tokenID containsString:classID] ? @"*" : @" ";
      [status appendFormat:@"  > %@ %@\n", marker, tokenID];
    }
  }
  [status appendString:@"\n"];

  if (pkcs11Tool && modulePath) {
    [status appendString:@"  PKCS#11 Slots\n"];
    [status appendFormat:@"  > %@\n",
                         [self runCommand:pkcs11Tool
                                arguments:@[
                                  @"--module", modulePath, @"--list-slots"
                                ]]];
    [status appendString:@"  Public Keys\n"];
    [status appendFormat:@"  > %@\n",
                         [self runCommand:pkcs11Tool
                                arguments:@[
                                  @"--module", modulePath, @"--list-objects",
                                  @"--type", @"pubkey"
                                ]]];
  } else if (!modulePath) {
    [status appendString:
                @"  PKCS#11\n  > Library not found (install IDplugManager)\n"];
  } else {
    [status appendString:
                @"  PKCS#11\n  > pkcs11-tool not found (install OpenSC)\n"];
  }
  [status appendString:@"Done.\n"];
  return status;
}

/// Refreshes the status display in the GUI.
/// Runs multiple diagnostic checks asynchronously and updates status rows.
///
/// @param sender The control that triggered the action (nil for programmatic calls)
- (IBAction)refreshStatus:(id)sender {
  if (self.cliMode) {
    [self emitStatus:[self checkTokenStatus]];
    return;
  }

  [self clearResults];
  self.checkButton.enabled = NO;

  // Create all 4 rows with waiting states for dependencies
  NSUInteger extRow = [self addRowWithTitle:@"Extension Active" waiting:NO];
  NSUInteger cardRow = [self addRowWithTitle:@"eID Card Detected" waiting:YES];
  NSUInteger readRow = [self addRowWithTitle:@"eID Card Readable" waiting:YES];
  NSUInteger regRow = [self addRowWithTitle:@"eID Registered with macOS"
                                    waiting:YES];

  NSString *modulePath = [self pkcs11ModulePath];
  NSString *pkcs11Tool = [self pkcs11ToolPath];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // 1. Extension Active (CryptoTokenKit Tokens)
    NSArray<NSString *> *allTokenIDs = [self allTokenIDs];
    NSString *classID = @"com.andrei.rocei.connector.extension";
    BOOL extensionFound = NO;
    NSMutableString *tokenDetail = [NSMutableString string];
    for (NSString *tid in allTokenIDs) {
      if ([tid containsString:classID])
        extensionFound = YES;
      [tokenDetail appendFormat:@"%@%@\n",
                                [tid containsString:classID] ? @"* " : @"  ",
                                tid];
    }
    if (allTokenIDs.count == 0)
      [tokenDetail appendString:@"No tokens registered\n"];

    if (extensionFound) {
      [self
          completeRow:extRow
              success:YES
              summary:[NSString
                          stringWithFormat:@"Registered (%lu token%@)",
                                           (unsigned long)allTokenIDs.count,
                                           allTokenIDs.count == 1 ? @"" : @"s"]
               detail:tokenDetail];
    } else if (allTokenIDs.count > 0) {
      [self completeRow:extRow
                warning:@"Tokens found, but eID extension not registered"
                 detail:tokenDetail];
    } else {
      [self completeRow:extRow
                success:NO
                summary:@"No tokens registered"
                 detail:tokenDetail];
    }

    // 2. eID Card Detected (PKCS#11 Slots)
    [self startRow:cardRow];
    if (!pkcs11Tool || !modulePath) {
      NSString *reason =
          !modulePath ? @"PKCS#11 library not found (install IDplugManager)"
                      : @"pkcs11-tool not found (install OpenSC)";
      [self completeRow:cardRow warning:reason detail:nil];
      [self completeRow:readRow
                warning:@"Skipped — dependencies missing"
                 detail:nil];
    } else {
      NSString *slotsRaw =
          [self runCommand:pkcs11Tool
                 arguments:@[ @"--module", modulePath, @"--list-slots" ]];
      NSUInteger activeSlots = [self countActiveSlotsInOutput:slotsRaw];
      if ([slotsRaw containsString:@"ERROR"] ||
          [slotsRaw containsString:@"TIMED OUT"]) {
        [self completeRow:cardRow
                  success:NO
                  summary:@"Error reading card"
                   detail:slotsRaw];
      } else if (activeSlots > 0) {
        [self completeRow:cardRow
                  success:YES
                  summary:[NSString
                              stringWithFormat:@"%lu active slot%@",
                                               (unsigned long)activeSlots,
                                               activeSlots == 1 ? @"" : @"s"]
                   detail:slotsRaw];
      } else {
        [self completeRow:cardRow
                  success:NO
                  summary:@"No card in reader"
                   detail:slotsRaw];
      }

      // 3. eID Card Readable (Public Keys)
      [self startRow:readRow];
      NSString *keysRaw = [self
          runCommand:pkcs11Tool
           arguments:@[
             @"--module", modulePath, @"--list-objects", @"--type", @"pubkey"
           ]];
      NSUInteger keyCount = [self countPublicKeysInOutput:keysRaw];
      if ([keysRaw containsString:@"ERROR"] ||
          [keysRaw containsString:@"TIMED OUT"]) {
        [self completeRow:readRow
                  success:NO
                  summary:@"Error reading card data"
                   detail:keysRaw];
      } else if (keyCount > 0) {
        [self completeRow:readRow
                  success:YES
                  summary:[NSString stringWithFormat:@"%lu public key%@ found",
                                                     (unsigned long)keyCount,
                                                     keyCount == 1 ? @"" : @"s"]
                   detail:keysRaw];
      } else {
        [self completeRow:readRow
                  success:NO
                  summary:@"No public keys found"
                   detail:keysRaw];
      }
    }

    // 4. eID Registered with macOS (sc_auth identities)
    [self startRow:regRow];
    NSString *scRaw = [self runCommand:@"/usr/sbin/sc_auth"
                             arguments:@[ @"identities" ]];
    NSString *trimmed = [scRaw
        stringByTrimmingCharactersInSet:[NSCharacterSet
                                            whitespaceAndNewlineCharacterSet]];
    BOOL hasIdentities =
        (trimmed.length > 0 && ![trimmed containsString:@"no output"] &&
         ![trimmed containsString:@"ERROR"]);
    // Count identity lines (lines with a tab = hash + name pairs)
    NSUInteger identityCount = 0;
    if (hasIdentities) {
      for (NSString *line in [trimmed componentsSeparatedByString:@"\n"]) {
        if ([line containsString:@"\t"])
          identityCount++;
      }
    }
    if (identityCount > 0) {
      [self completeRow:regRow
                success:YES
                summary:[NSString stringWithFormat:@"%lu identity registered",
                                                   (unsigned long)identityCount]
                 detail:scRaw];
    } else {
      [self completeRow:regRow
                success:NO
                summary:@"No identities registered"
                 detail:scRaw];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      self.checkButton.enabled = YES;
    });
  });
}

/// Count active (non-empty) PKCS#11 slots in raw output.
/// Counts the number of active (token-present) PKCS#11 slots in pkcs11-tool
/// output by scanning for "token present" lines.
///
/// @param raw Raw pkcs11-tool --list-slots output
/// @return Number of slots with a token present
- (NSUInteger)countActiveSlotsInOutput:(NSString *)raw {
  NSUInteger count = 0;
  BOOL inSlot = NO;
  BOOL isEmpty = NO;
  for (NSString *line in [raw componentsSeparatedByString:@"\n"]) {
    if ([line hasPrefix:@"Slot "] || [line hasPrefix:@"  Slot "]) {
      if (inSlot && !isEmpty)
        count++;
      inSlot = YES;
      isEmpty = NO;
    } else if (inSlot) {
      NSString *l =
          [line stringByTrimmingCharactersInSet:[NSCharacterSet
                                                    whitespaceCharacterSet]];
      if ([l isEqualToString:@"(empty)"])
        isEmpty = YES;
    }
  }
  if (inSlot && !isEmpty)
    count++;
  return count;
}

/// Count public keys in pkcs11-tool output.
/// Counts public key objects in pkcs11-tool --list-objects output.
///
/// @param raw Raw pkcs11-tool output
/// @return Number of lines containing "Public Key Object"
- (NSUInteger)countPublicKeysInOutput:(NSString *)raw {
  NSUInteger count = 0;
  for (NSString *line in [raw componentsSeparatedByString:@"\n"]) {
    if ([line containsString:@"Public Key Object"])
      count++;
  }
  return count;
}

// (Old text-based parsers removed — replaced by GUI row system)

/// Returns all CryptoTokenKit token IDs currently registered in the system.
///
/// @return Array of token ID strings (may be empty)
- (NSArray<NSString *> *)allTokenIDs {
  TKTokenWatcher *watcher = [[TKTokenWatcher alloc] init];
  return watcher.tokenIDs ?: @[];
}

/// Finds the first CryptoTokenKit token ID matching our extension's class ID.
///
/// @return Token ID containing "com.andrei.rocei.connector.extension", or nil
- (NSString *)matchingExtensionID {
  NSString *classID = @"com.andrei.rocei.connector.extension";
  for (NSString *tokenID in [self allTokenIDs]) {
    if ([tokenID containsString:classID]) {
      return tokenID;
    }
  }
  return nil;
}

/// Performs smart card diagnostics by probing all detected card readers.
/// Sends SELECT APDUs for Romanian eID and PIV application identifiers
/// and reports the response status words.
///
/// @return Multi-line diagnostic output with reader/card details
- (NSString *)smartCardDiagnostic {
  TKSmartCardSlotManager *manager = [TKSmartCardSlotManager defaultManager];
  if (manager == nil) {
    return @"TKSmartCardSlotManager.defaultManager is nil (missing "
           @"com.apple.security.smartcard entitlement?)\n";
  }

  NSMutableString *out = [NSMutableString string];
  if (manager.slotNames.count == 0) {
    [out appendString:@"No smart card slots detected.\n"];
    return out;
  }

  NSArray<NSData *> *aidList = @[
    [self dataFromHexString:@"E828BD080FD25047656E65726963"],
    [self dataFromHexString:@"a00000030800001000"], // PIV
  ];

  for (NSString *slotName in manager.slotNames) {
    TKSmartCardSlot *slot = [manager slotNamed:slotName];
    if (!slot) {
      [out appendFormat:@"%@: slot not found\n", slotName];
      continue;
    }
    [out appendFormat:@"%@: state=%ld\n", slot.name, (long)slot.state];
    if (slot.ATR.bytes.length > 0) {
      [out
          appendFormat:@"  ATR: %@\n", [self hexStringFromData:slot.ATR.bytes]];
    }

    if (slot.state != TKSmartCardSlotStateValidCard) {
      continue;
    }

    TKSmartCard *card = [slot makeSmartCard];
    if (!card) {
      [out appendString:@"  makeSmartCard failed\n"];
      continue;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL sessionOK = NO;
    __block NSError *sessionError = nil;
    [card beginSessionWithReply:^(BOOL success, NSError *_Nullable error) {
      sessionOK = success;
      sessionError = error;
      dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    if (!sessionOK) {
      [out appendFormat:@"  beginSession failed: %@\n",
                        sessionError.localizedDescription ?: @"(unknown)"];
      continue;
    }

    for (NSData *aid in aidList) {
      if (aid.length == 0) {
        continue;
      }
      for (NSNumber *p2 in @[ @0x00, @0x0C ]) {
        NSData *apdu = [self apduSelectForAID:aid p2:p2.unsignedCharValue];
        dispatch_semaphore_t apduSem = dispatch_semaphore_create(0);
        __block NSData *response = nil;
        __block NSError *apduError = nil;
        [card transmitRequest:apdu
                        reply:^(NSData *_Nullable responseData,
                                NSError *_Nullable error) {
                          response = responseData;
                          apduError = error;
                          dispatch_semaphore_signal(apduSem);
                        }];
        dispatch_semaphore_wait(apduSem, DISPATCH_TIME_FOREVER);
        if (apduError) {
          [out appendFormat:@"  SELECT %@ (P2=%02X) -> error: %@\n",
                            [self hexStringFromData:aid], p2.unsignedCharValue,
                            apduError.localizedDescription];
          continue;
        }
        if (response.length < 2) {
          [out appendFormat:
                   @"  SELECT %@ (P2=%02X) -> short response (%lu bytes)\n",
                   [self hexStringFromData:aid], p2.unsignedCharValue,
                   (unsigned long)response.length];
          continue;
        }
        const unsigned char *bytes = response.bytes;
        UInt8 sw1 = bytes[response.length - 2];
        UInt8 sw2 = bytes[response.length - 1];
        [out appendFormat:@"  SELECT %@ (P2=%02X) -> SW=%02X%02X (len=%lu)\n",
                          [self hexStringFromData:aid], p2.unsignedCharValue,
                          sw1, sw2, (unsigned long)response.length];
      }
    }

    [card endSession];
  }

  return out;
}

/// Builds a SELECT APDU command for the given Application Identifier.
///
/// @param aid Application Identifier data
/// @param p2 P2 byte (0x00 for first/only, 0x0C for selection by name)
/// @return Complete APDU command data
- (NSData *)apduSelectForAID:(NSData *)aid p2:(uint8_t)p2 {
  NSMutableData *apdu = [NSMutableData dataWithCapacity:(6 + aid.length)];
  uint8_t header[] = {0x00, 0xA4, 0x04, p2, (uint8_t)aid.length};
  [apdu appendBytes:header length:sizeof(header)];
  [apdu appendData:aid];
  uint8_t le = 0x00;
  [apdu appendBytes:&le length:1];
  return apdu;
}

/// Converts binary data to uppercase hexadecimal string.
///
/// @param data Binary data to convert
/// @return Hexadecimal string (e.g., "A1B2C3")
- (NSString *)hexStringFromData:(NSData *)data {
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

/// Converts a hexadecimal string to binary data.
/// Strips non-hex characters before conversion.
///
/// @param hexString Hexadecimal string (e.g., "A1B2C3")
/// @return Binary data
- (NSData *)dataFromHexString:(NSString *)hexString {
  NSString *clean = [[hexString
      componentsSeparatedByCharactersInSet:
          [[NSCharacterSet
              characterSetWithCharactersInString:@"0123456789abcdefABCDEF"]
              invertedSet]] componentsJoinedByString:@""];
  NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
  unsigned char byte = 0;
  for (NSUInteger i = 0; i + 1 < clean.length; i += 2) {
    NSString *pair = [clean substringWithRange:NSMakeRange(i, 2)];
    byte = (unsigned char)strtoul(pair.UTF8String, NULL, 16);
    [data appendBytes:&byte length:1];
  }
  return data;
}

/// Determines EC key size from DER-encoded EC parameters OID string.
///
/// @param ecParams Hex string containing DER-encoded EC OID
/// @return Key size in bits (256 for secp256r1, 384 for secp384r1), or nil
- (nullable NSNumber *)keySizeBitsFromECParamsString:(NSString *)ecParams {
  NSString *clean =
      [[ecParams lowercaseString] stringByReplacingOccurrencesOfString:@" "
                                                            withString:@""];
  if ([clean containsString:@"06052b81040022"]) {
    return @(384);
  }
  if ([clean containsString:@"06082a8648ce3d030107"]) {
    return @(256);
  }
  return nil;
}

/// Parses pkcs11-tool public key object output to extract key ID, EC point,
/// and key size.
///
/// @param output Raw pkcs11-tool --list-objects output
/// @param keyIdOut On return, binary key ID (from hex representation)
/// @param ecPointOut On return, DER-encoded EC public key point
/// @param keyBitsOut On return, key size in bits (256 or 384)
/// @return YES if all required fields were found
- (BOOL)
    parsePublicKeyInfoFromPkcs11Output:(NSString *)output
                              keyIdOut:
                                  (NSData *__autoreleasing _Nullable *_Nullable)
                                      keyIdOut
                            ecPointOut:
                                (NSData *__autoreleasing _Nullable *_Nullable)
                                    ecPointOut
                            keyBitsOut:
                                (NSNumber *__autoreleasing _Nullable *_Nullable)
                                    keyBitsOut {
  NSString *idHex = nil;
  NSString *ecPointHex = nil;
  NSString *ecParamsHex = nil;

  NSArray<NSString *> *lines =
      [output componentsSeparatedByCharactersInSet:[NSCharacterSet
                                                       newlineCharacterSet]];
  for (NSString *line in lines) {
    if ([line containsString:@"EC_POINT:"]) {
      NSRange range = [line rangeOfString:@"EC_POINT:"];
      ecPointHex = [[line substringFromIndex:NSMaxRange(range)]
          stringByTrimmingCharactersInSet:[NSCharacterSet
                                              whitespaceCharacterSet]];
    } else if ([line containsString:@"EC_PARAMS:"]) {
      NSRange range = [line rangeOfString:@"EC_PARAMS:"];
      ecParamsHex = [[line substringFromIndex:NSMaxRange(range)]
          stringByTrimmingCharactersInSet:[NSCharacterSet
                                              whitespaceCharacterSet]];
    } else if ([line containsString:@"ID:"]) {
      NSRange range = [line rangeOfString:@"ID:"];
      idHex = [[line substringFromIndex:NSMaxRange(range)]
          stringByTrimmingCharactersInSet:[NSCharacterSet
                                              whitespaceCharacterSet]];
    }
  }

  if (idHex.length == 0 || ecPointHex.length == 0) {
    return NO;
  }

  NSData *keyId = [self dataFromHexString:idHex];
  NSData *ecPoint = [self dataFromHexString:ecPointHex];
  if (keyId.length == 0 || ecPoint.length == 0) {
    return NO;
  }

  if (keyIdOut)
    *keyIdOut = keyId;
  if (ecPointOut)
    *ecPointOut = ecPoint;
  if (keyBitsOut)
    *keyBitsOut = [self keySizeBitsFromECParamsString:ecParamsHex];
  return YES;
}

/// Queries the Security framework keychain for key items associated with
/// a CryptoTokenKit token and formats their attributes.
///
/// @param tokenID The token ID to search for
/// @return Multi-line listing of key label, class, type, and size
- (NSString *)dumpTokenKeysForTokenID:(NSString *)tokenID {
  NSMutableString *out = [NSMutableString string];
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrTokenID : tokenID,
    (__bridge id)kSecReturnAttributes : @YES,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll
  };

  CFTypeRef result = NULL;
  OSStatus statusCode =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (statusCode == errSecItemNotFound) {
    [out appendString:@"No key items found for token.\n"];
    return out;
  }
  if (statusCode != errSecSuccess || result == NULL) {
    [out appendFormat:@"Key item query failed (status=%d).\n", (int)statusCode];
    return out;
  }

  NSArray *items = CFBridgingRelease(result);
  if (![items isKindOfClass:[NSArray class]]) {
    items = @[ (id)items ];
  }

  for (NSDictionary *attrs in items) {
    NSString *label = attrs[(__bridge id)kSecAttrLabel] ?: @"(no label)";
    id keyClass = attrs[(__bridge id)kSecAttrKeyClass] ?: @"(unknown class)";
    id keyType = attrs[(__bridge id)kSecAttrKeyType] ?: @"(unknown type)";
    id keySize = attrs[(__bridge id)kSecAttrKeySizeInBits] ?: @"(unknown size)";
    [out appendFormat:@"- label=%@ class=%@ type=%@ size=%@\n", label, keyClass,
                      keyType, keySize];
  }
  return out;
}

/// CLI: performs a full token initialization test.
/// Finds the CryptoTokenKit token, locates a signing key via the Security
/// framework, and performs a test SHA-256 signature to verify PIN acceptance
/// and certificate caching.
///
/// @return Multi-line status report
- (NSString *)initializeTokenStatus {
  NSMutableString *status = [NSMutableString string];
  NSString *tokenID = [self matchingExtensionID];
  if (tokenID.length == 0) {
    [status appendString:
                @"[initialize] No ROCEI tokenID found via CryptoTokenKit.\n"];
    NSArray<NSString *> *allTokenIDs = [self allTokenIDs];
    if (allTokenIDs.count == 0) {
      [status appendString:@"TokenIDs list is empty. Ensure the card is "
                           @"inserted and the AID matches.\n"];
    } else {
      [status appendString:@"Observed tokenIDs:\n"];
      for (NSString *candidate in allTokenIDs) {
        [status appendFormat:@"- %@\n", candidate];
      }
      [status
          appendString:@"None matched com.andrei.rocei.connector.extension\n"];
    }
    return status;
  }
  [status appendFormat:@"[initialize] Using tokenID: %@\n", tokenID];
  [status appendString:@"Looking up token key by label...\n"];

  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassKey,
    (__bridge id)kSecAttrTokenID : tokenID,
    (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
    (__bridge id)kSecAttrLabel : @"RO CEI Authentication Key",
    (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
    (__bridge id)kSecReturnRef : @YES,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
  };

  SecKeyRef keyRef = NULL;
  OSStatus statusCode = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                            (CFTypeRef *)&keyRef);
  if (statusCode != errSecSuccess || keyRef == NULL) {
    [status
        appendFormat:
            @"Key by label not found (status=%d). Trying fallback query...\n",
            (int)statusCode];
    NSDictionary *fallback = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassKey,
      (__bridge id)kSecAttrTokenID : tokenID,
      (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
      (__bridge id)
      kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
      (__bridge id)kSecReturnRef : @YES,
      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
    };
    statusCode = SecItemCopyMatching((__bridge CFDictionaryRef)fallback,
                                     (CFTypeRef *)&keyRef);
    if (statusCode != errSecSuccess || keyRef == NULL) {
      [status appendFormat:@"Failed to find any EC key in token (status=%d).\n",
                           (int)statusCode];
      [status appendString:@"Token key inventory:\n"];
      [status appendString:[self dumpTokenKeysForTokenID:tokenID]];
      return status;
    }
  }

  // Determine key size and select appropriate algorithm
  NSDictionary *attrs = CFBridgingRelease(SecKeyCopyAttributes(keyRef));
  NSNumber *keySizeInBits = attrs[(__bridge id)kSecAttrKeySizeInBits];
  NSInteger keySize = keySizeInBits ? keySizeInBits.integerValue : 256;

  SecKeyAlgorithm alg;
  NSData *digestData;
  if (keySize >= 384) {
    // Use SHA-384 for 384-bit keys
    uint8_t digest[48] = {0};
    for (int i = 0; i < 48; i++)
      digest[i] = (uint8_t)i;
    digestData = [NSData dataWithBytes:digest length:sizeof(digest)];
    alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
    [status appendFormat:@"Testing 384-bit key with SHA-384...\n"];
  } else {
    // Use SHA-256 for 256-bit keys
    uint8_t digest[32] = {0};
    for (int i = 0; i < 32; i++)
      digest[i] = (uint8_t)i;
    digestData = [NSData dataWithBytes:digest length:sizeof(digest)];
    alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    [status appendFormat:@"Testing 256-bit key with SHA-256...\n"];
  }

  if (!SecKeyIsAlgorithmSupported(keyRef, kSecKeyOperationTypeSign, alg)) {
    [status appendFormat:@"Key does not support algorithm %@.\n", alg];
    if (keyRef)
      CFRelease(keyRef);
    return status;
  }

  CFErrorRef error = NULL;
  CFDataRef sig = SecKeyCreateSignature(keyRef, alg,
                                        (__bridge CFDataRef)digestData, &error);
  if (sig == NULL) {
    [status appendFormat:@"Signature failed: %@\n",
                         error ? CFBridgingRelease(error) : @"(unknown error)"];
    if (keyRef)
      CFRelease(keyRef);
    return status;
  }

  [status appendString:@"Signature OK. PIN accepted. The extension should now "
                       @"cache the certificate for sc_auth.\n"];
  if (sig)
    CFRelease(sig);
  if (keyRef)
    CFRelease(keyRef);
  return status;
}

/// GUI: performs the same initialization test as initializeTokenStatus
/// with visual progress rows for "Find Token", "Find Signing Key", and
/// "Test Signature".
///
/// @param sender The button that triggered the action
- (IBAction)initializeToken:(id)sender {
  if (self.cliMode) {
    [self emitStatus:[self initializeTokenStatus]];
    return;
  }
  [self clearResults];
  self.setupButton.enabled = NO;

  NSUInteger tokenRow = [self addRowWithTitle:@"Find Token" waiting:NO];
  NSUInteger keyRow = [self addRowWithTitle:@"Find Signing Key" waiting:YES];
  NSUInteger signRow = [self addRowWithTitle:@"Test Signature" waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSString *tokenID = [self matchingExtensionID];
    if (tokenID.length == 0) {
      NSMutableString *detail = [NSMutableString string];
      NSArray<NSString *> *allTokenIDs = [self allTokenIDs];
      if (allTokenIDs.count == 0) {
        [detail appendString:@"TokenIDs list is empty."];
      } else {
        [detail appendString:@"Observed tokenIDs:\n"];
        for (NSString *t in allTokenIDs)
          [detail appendFormat:@"- %@\n", t];
        [detail
            appendString:@"None matched com.andrei.rocei.connector.extension"];
      }
      [self completeRow:tokenRow
                success:NO
                summary:@"eID token not found"
                 detail:detail];
      [self completeRow:keyRow success:NO summary:@"Skipped" detail:nil];
      [self completeRow:signRow success:NO summary:@"Skipped" detail:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        self.setupButton.enabled = YES;
      });
      return;
    }
    [self completeRow:tokenRow success:YES summary:tokenID detail:nil];

    // Find key
    [self startRow:keyRow];
    NSDictionary *query = @{
      (__bridge id)kSecClass : (__bridge id)kSecClassKey,
      (__bridge id)kSecAttrTokenID : tokenID,
      (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
      (__bridge id)
      kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
      (__bridge id)kSecReturnRef : @YES,
      (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
    };
    SecKeyRef keyRef = NULL;
    OSStatus statusCode = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                              (CFTypeRef *)&keyRef);
    if (statusCode != errSecSuccess || keyRef == NULL) {
      NSString *detail =
          [NSString stringWithFormat:@"SecItemCopyMatching status=%d\n\n%@",
                                     (int)statusCode,
                                     [self dumpTokenKeysForTokenID:tokenID]];
      [self completeRow:keyRow
                success:NO
                summary:@"No EC key found"
                 detail:detail];
      [self completeRow:signRow success:NO summary:@"Skipped" detail:nil];
      dispatch_async(dispatch_get_main_queue(), ^{
        self.setupButton.enabled = YES;
      });
      return;
    }

    NSDictionary *attrs = CFBridgingRelease(SecKeyCopyAttributes(keyRef));
    NSNumber *keySizeInBits = attrs[(__bridge id)kSecAttrKeySizeInBits];
    NSInteger keySize = keySizeInBits ? keySizeInBits.integerValue : 256;
    [self
        completeRow:keyRow
            success:YES
            summary:[NSString stringWithFormat:@"EC %ld-bit key", (long)keySize]
             detail:nil];

    // Sign
    [self startRow:signRow];
    SecKeyAlgorithm alg;
    NSData *digestData;
    if (keySize >= 384) {
      uint8_t digest[48] = {0};
      for (int i = 0; i < 48; i++)
        digest[i] = (uint8_t)i;
      digestData = [NSData dataWithBytes:digest length:sizeof(digest)];
      alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
    } else {
      uint8_t digest[32] = {0};
      for (int i = 0; i < 32; i++)
        digest[i] = (uint8_t)i;
      digestData = [NSData dataWithBytes:digest length:sizeof(digest)];
      alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    }

    if (!SecKeyIsAlgorithmSupported(keyRef, kSecKeyOperationTypeSign, alg)) {
      [self completeRow:signRow
                success:NO
                summary:@"Algorithm not supported"
                 detail:nil];
      CFRelease(keyRef);
      dispatch_async(dispatch_get_main_queue(), ^{
        self.setupButton.enabled = YES;
      });
      return;
    }

    CFErrorRef error = NULL;
    CFDataRef sig = SecKeyCreateSignature(
        keyRef, alg, (__bridge CFDataRef)digestData, &error);
    if (sig == NULL) {
      NSString *errMsg = error
                             ? [(__bridge NSError *)error localizedDescription]
                             : @"unknown error";
      if (error)
        CFRelease(error);
      [self completeRow:signRow success:NO summary:errMsg detail:nil];
    } else {
      [self completeRow:signRow
                success:YES
                summary:@"Signature OK — PIN accepted"
                 detail:nil];
      CFRelease(sig);
    }
    CFRelease(keyRef);
    dispatch_async(dispatch_get_main_queue(), ^{
      self.setupButton.enabled = YES;
    });
  });
}

#pragma mark - ROCEIProgressProtocol (called by helper via XPC)

/// Updates the progress row in the GUI with the current step description.
/// Used as a callback during long-running XPC operations.
///
/// @param step Description of the current operation step
- (void)reportProgress:(NSString *)step {
  os_log(OS_LOG_DEFAULT, "Connector: [Helper] %{public}@", step);
}

/// CLI: registers a persistent token via the XPC helper.
/// Connects to the helper service, reads certificates from
/// the PKCS#11 module, and registers them as keychain items
/// through TKTokenDriverConfiguration.
///
/// @return Multi-line status report of the registration
- (NSString *)registerPersistentTokenStatus {
  // CLI-only path — returns plain text
  // NOTE: This method does NOT require a PIN. Token registration reads public
  // certificates which are accessible without authentication (CKF_TOKEN_INITIALIZED).
  // PIN is only required later during C_Sign operations, which should be done
  // through the GUI where PIN entry is secure and not visible in process listings.
  NSMutableString *status = [NSMutableString string];
  if (@available(macOS 10.15, *)) {
    NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *> *configs =
        TKTokenDriverConfiguration.driverConfigurations;
    TKTokenDriverConfiguration *config =
        configs[@"com.andrei.rocei.connector.extension"];
    if (!config) {
      [status appendString:@"ERROR: Token driver configuration not found.\n"];
      return status;
    }
    NSString *instanceID = @"rocei-pkcs11";
    TKTokenConfiguration *tokenConfig =
        [config addTokenConfigurationForTokenInstanceID:instanceID];
    NSString *modulePath = [self pkcs11ModulePath];
    if (!modulePath) {
      [status appendString:@"ERROR: PKCS#11 library not found.\n"];
      return status;
    }
    NSString *configDir = [modulePath stringByDeletingLastPathComponent];
    NSString *slotArg = self.cliSlot ?: @"0x1";

    // SECURITY: Validate slot is one of the three valid Romanian eID slots
    // Slot 0x1 = Authentication, 0x2 = Digital Signature, 0x3 = Key Encryption
    char *endptr = NULL;
    unsigned long slotValue = strtoul([slotArg UTF8String], &endptr, 0);

    // Validate parsing succeeded and slot is in valid range
    if (endptr == [slotArg UTF8String] || *endptr != '\0') {
      [status appendFormat:@"ERROR: Invalid slot format '%@'. Use hex (0x1, "
                           @"0x2, 0x3) or decimal (1, 2, 3).\n",
                           slotArg];
      return status;
    }

    if (slotValue != 0x1 && slotValue != 0x2 && slotValue != 0x3) {
      [status appendFormat:@"ERROR: Invalid slot %lu. Must be 0x1 (auth), 0x2 "
                           @"(sign), or 0x3 (encrypt).\n",
                           slotValue];
      return status;
    }

    NSNumber *slotNum = @(slotValue);

    NSXPCConnection *connection = [self helperConnection];
    if (!connection) {
      [status appendString:@"ERROR: No XPC connection.\n"];
      return status;
    }

    __block NSArray<ROCEICertificateInfo *> *certInfos = nil;
    __block NSError *xpcError = nil;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __weak dispatch_semaphore_t weakSema = sema;
    id<ROCEISigningServiceProtocol> helper =
        [connection remoteObjectProxyWithErrorHandler:^(NSError *proxyError) {
          xpcError = proxyError;
          dispatch_semaphore_t strongSema = weakSema;
          if (strongSema) {
            dispatch_semaphore_signal(strongSema);
          }
        }];
    [helper
        enumerateCertificatesWithSlot:slotNum
                                reply:^(NSArray<ROCEICertificateInfo *> *items,
                                        NSError *error) {
                                  certInfos = items;
                                  xpcError = error;
                                  dispatch_semaphore_t strongSema = weakSema;
                                  if (strongSema) {
                                    dispatch_semaphore_signal(strongSema);
                                  }
                                }];
    dispatch_time_t timeout =
        dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, timeout) != 0) {
      [status appendString:@"XPC timed out.\n"];
      return status;
    }
    if (xpcError || certInfos.count == 0) {
      [status appendFormat:@"ERROR: %@\n",
                           xpcError.localizedDescription ?: @"No certificates"];
      return status;
    }

    ROCEICertificateInfo *info = certInfos.firstObject;
    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[@"modulePath"] = modulePath;
    payload[@"configDir"] = configDir;
    payload[@"slot"] = slotArg;
    payload[@"certificateDER"] =
        [info.certificateDER base64EncodedStringWithOptions:0];
    payload[@"keyID"] = [info.keyID base64EncodedStringWithOptions:0];
    payload[@"publicKeyData"] =
        info.publicKeyData
            ? [info.publicKeyData base64EncodedStringWithOptions:0]
            : @"";
    payload[@"keySizeBits"] = @(info.keySizeBits);
    tokenConfig.configurationData =
        [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];

    SecCertificateRef certRef = SecCertificateCreateWithData(
        NULL, (__bridge CFDataRef)info.certificateDER);
    if (certRef) {
      TKTokenKeychainKey *keyItem =
          [[TKTokenKeychainKey alloc] initWithCertificate:certRef
                                                 objectID:info.keyID];
      keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom;
      keyItem.keySizeInBits = info.keySizeBits;
      keyItem.publicKeyData = info.publicKeyData;
      keyItem.label = @"RO CEI Authentication Key";
      keyItem.canSign = YES;
      keyItem.suitableForLogin = YES;
      NSMutableDictionary<NSNumber *, TKTokenOperationConstraint> *constraints =
          [NSMutableDictionary dictionary];
      constraints[@(TKTokenOperationSignData)] = @"PIN";
      keyItem.constraints = constraints;

      TKTokenKeychainCertificate *certItem =
          [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef
                                                         objectID:info.keyID];
      certItem.label = @"RO CEI Authentication Certificate";
      tokenConfig.keychainItems = @[ keyItem, certItem ];

      [status appendFormat:@"Registered: %@ (%lu bits)\n", keyItem.label,
                           (unsigned long)info.keySizeBits];
      CFRelease(certRef);
    }
  }
  return status;
}

/// GUI: registers a persistent token via the XPC helper with visual
/// progress rows for "Token Driver", "Read Certificate", "Configure Token",
/// and "Register Keychain Items".
///
/// @param sender The button that triggered the action
- (IBAction)registerPersistentToken:(id)sender {
  [self clearResults];
  self.registerButton.enabled = NO;

  NSUInteger driverRow = [self addRowWithTitle:@"Token Driver" waiting:NO];
  NSUInteger xpcRow = [self addRowWithTitle:@"Read Certificate" waiting:YES];
  NSUInteger configRow = [self addRowWithTitle:@"Configure Token" waiting:YES];
  NSUInteger keychainRow = [self addRowWithTitle:@"Register Keychain Items"
                                         waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    if (@available(macOS 10.15, *)) {
      // 1. Look up token driver
      [self startRow:driverRow];
      NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *>
          *configs = TKTokenDriverConfiguration.driverConfigurations;
      TKTokenDriverConfiguration *config =
          configs[@"com.andrei.rocei.connector.extension"];
      if (!config) {
        NSString *detail = [NSString
            stringWithFormat:
                @"Available drivers: %@\n\nTroubleshooting:\n1. Restart the "
                @"Mac\n2. Or try: sudo killall -9 ctkd && sleep 2",
                configs.allKeys];
        [self completeRow:driverRow
                  success:NO
                  summary:@"Driver not found"
                   detail:detail];
        [self completeRow:xpcRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }

      NSString *modulePath = [self pkcs11ModulePath];
      if (!modulePath) {
        [self completeRow:driverRow
                  success:NO
                  summary:@"PKCS#11 library not found"
                   detail:@"Install IDplugManager first."];
        [self completeRow:xpcRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }
      [self completeRow:driverRow
                success:YES
                summary:@"Driver found"
                 detail:nil];

      // 2. Read certificate via XPC helper
      [self startRow:xpcRow];
      NSString *configDir = [modulePath stringByDeletingLastPathComponent];
      NSString *slotArg = self.cliSlot ?: @"0x1";

      // SECURITY: Validate slot is one of the three valid Romanian eID slots
      // Slot 0x1 = Authentication, 0x2 = Digital Signature, 0x3 = Key Encryption
      char *endptr = NULL;
      unsigned long slotValue = strtoul([slotArg UTF8String], &endptr, 0);

      // Validate parsing succeeded and slot is in valid range
      if (endptr == [slotArg UTF8String] || *endptr != '\0') {
        NSString *detail = [NSString
            stringWithFormat:@"Invalid slot format '%@'. Use hex (0x1, 0x2, "
                             @"0x3) or decimal (1, 2, 3).",
                             slotArg];
        [self completeRow:xpcRow
                  success:NO
                  summary:@"Invalid slot format"
                   detail:detail];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }

      if (slotValue != 0x1 && slotValue != 0x2 && slotValue != 0x3) {
        NSString *detail = [NSString
            stringWithFormat:@"Invalid slot %lu. Must be 0x1 (auth), 0x2 "
                             @"(sign), or 0x3 (encrypt).",
                             slotValue];
        [self completeRow:xpcRow
                  success:NO
                  summary:@"Invalid slot number"
                   detail:detail];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }

      NSNumber *slotNum = @(slotValue);

      NSXPCConnection *connection = [self helperConnection];
      if (!connection) {
        [self completeRow:xpcRow
                  success:NO
                  summary:@"XPC connection failed"
                   detail:@"Is the helper registered? Run: launchctl list | "
                          @"grep ROCEIHelper"];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }

      __block NSArray<ROCEICertificateInfo *> *certInfos = nil;
      __block NSError *xpcError = nil;
      dispatch_semaphore_t sema = dispatch_semaphore_create(0);
      __weak dispatch_semaphore_t weakSema = sema;
      id<ROCEISigningServiceProtocol> helper =
          [connection remoteObjectProxyWithErrorHandler:^(NSError *proxyError) {
            os_log_error(OS_LOG_DEFAULT,
                         "Connector: XPC proxy error: %{public}@", proxyError);
            xpcError = proxyError;
            dispatch_semaphore_t strongSema = weakSema;
            if (strongSema) {
              dispatch_semaphore_signal(strongSema);
            }
          }];
      [helper
          enumerateCertificatesWithSlot:slotNum
                                  reply:^(
                                      NSArray<ROCEICertificateInfo *> *items,
                                      NSError *error) {
                                    certInfos = items;
                                    xpcError = error;
                                    dispatch_semaphore_t strongSema = weakSema;
                                    if (strongSema) {
                                      dispatch_semaphore_signal(strongSema);
                                    }
                                  }];

      dispatch_time_t timeout =
          dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC);
      long timedOut = dispatch_semaphore_wait(sema, timeout);

      if (timedOut) {
        [self completeRow:xpcRow
                  success:NO
                  summary:@"Timed out (30s)"
                   detail:@"The PKCS#11 library may be blocked. Make sure card "
                          @"reader is connected and eID card is inserted."];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }
      if (xpcError || certInfos.count == 0) {
        NSString *msg =
            xpcError.localizedDescription ?: @"No certificates found by helper";
        [self completeRow:xpcRow
                  success:NO
                  summary:msg
                   detail:xpcError.description];
        [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.registerButton.enabled = YES;
        });
        return;
      }

      ROCEICertificateInfo *info = certInfos.firstObject;
      [self
          completeRow:xpcRow
              success:YES
              summary:[NSString
                          stringWithFormat:@"Certificate received (%lu bytes)",
                                           (unsigned long)
                                               info.certificateDER.length]
               detail:nil];

      // 3. Configure token
      [self startRow:configRow];
      NSString *instanceID = @"rocei-pkcs11";
      TKTokenConfiguration *tokenConfig =
          [config addTokenConfigurationForTokenInstanceID:instanceID];

      NSMutableDictionary *payload = [NSMutableDictionary dictionary];
      payload[@"modulePath"] = modulePath;
      payload[@"configDir"] = configDir;
      payload[@"slot"] = slotArg;
      payload[@"certificateDER"] =
          [info.certificateDER base64EncodedStringWithOptions:0];
      payload[@"keyID"] = [info.keyID base64EncodedStringWithOptions:0];
      payload[@"publicKeyData"] =
          info.publicKeyData
              ? [info.publicKeyData base64EncodedStringWithOptions:0]
              : @"";
      payload[@"keySizeBits"] = @(info.keySizeBits);
      tokenConfig.configurationData =
          [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
      os_log(OS_LOG_DEFAULT,
             "Connector: Set configurationData with cert (%lu bytes)",
             (unsigned long)info.certificateDER.length);
      [self completeRow:configRow
                success:YES
                summary:[NSString stringWithFormat:@"Instance: %@", instanceID]
                 detail:nil];

      // 4. Register keychain items
      [self startRow:keychainRow];
      SecCertificateRef certRef = SecCertificateCreateWithData(
          NULL, (__bridge CFDataRef)info.certificateDER);
      if (!certRef) {
        [self completeRow:keychainRow
                  success:NO
                  summary:@"Invalid certificate data"
                   detail:nil];
      } else {
        TKTokenKeychainKey *keyItem =
            [[TKTokenKeychainKey alloc] initWithCertificate:certRef
                                                   objectID:info.keyID];
        keyItem.keyType = (id)kSecAttrKeyTypeECSECPrimeRandom;
        keyItem.keySizeInBits = info.keySizeBits;
        keyItem.publicKeyData = info.publicKeyData;
        keyItem.label = @"RO CEI Authentication Key";
        keyItem.canSign = YES;
        keyItem.suitableForLogin = YES;
        NSMutableDictionary<NSNumber *, TKTokenOperationConstraint>
            *constraints = [NSMutableDictionary dictionary];
        constraints[@(TKTokenOperationSignData)] = @"PIN";
        keyItem.constraints = constraints;

        TKTokenKeychainCertificate *certItem =
            [[TKTokenKeychainCertificate alloc] initWithCertificate:certRef
                                                           objectID:info.keyID];
        certItem.label = @"RO CEI Authentication Certificate";
        tokenConfig.keychainItems = @[ keyItem, certItem ];
        CFRelease(certRef);

        [self completeRow:keychainRow
                  success:YES
                  summary:[NSString
                              stringWithFormat:@"%@ (%lu-bit)", keyItem.label,
                                               (unsigned long)info.keySizeBits]
                   detail:nil];
      }
    } else {
      [self completeRow:driverRow
                success:NO
                summary:@"Requires macOS 10.15+"
                 detail:nil];
      [self completeRow:xpcRow success:NO summary:@"Skipped" detail:nil];
      [self completeRow:configRow success:NO summary:@"Skipped" detail:nil];
      [self completeRow:keychainRow success:NO summary:@"Skipped" detail:nil];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      self.registerButton.enabled = YES;
    });
  });
}

/// GUI: removes the persistent token configuration and restarts the
/// CryptoTokenKit daemon. Clears all token configurations and keychain items
/// registered through TKTokenDriverConfiguration.
///
/// @param sender The button that triggered the action
- (IBAction)deregisterToken:(id)sender {
  [self clearResults];
  self.deregisterTokenButton.enabled = NO;

  NSUInteger configRow = [self addRowWithTitle:@"Find Token Configuration"
                                       waiting:NO];
  NSUInteger removeRow = [self addRowWithTitle:@"Remove Configuration"
                                       waiting:YES];
  NSUInteger restartRow = [self addRowWithTitle:@"Restart CTK Daemon"
                                        waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    if (@available(macOS 10.15, *)) {
      // 1. Find token driver and configuration
      NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *>
          *configs = TKTokenDriverConfiguration.driverConfigurations;
      TKTokenDriverConfiguration *config =
          configs[@"com.andrei.rocei.connector.extension"];

      if (!config) {
        [self completeRow:configRow
                  success:NO
                  summary:@"Driver not found"
                   detail:@"Extension not registered with CryptoTokenKit"];
        [self completeRow:removeRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:restartRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.deregisterTokenButton.enabled = YES;
        });
        return;
      }

      // Check if token instance exists
      NSString *instanceID = @"rocei-pkcs11";
      TKTokenConfiguration *tokenConfig =
          config.tokenConfigurations[instanceID];

      if (!tokenConfig) {
        [self completeRow:configRow
                  success:YES
                  summary:@"No token registered"
                   detail:@"Instance 'rocei-pkcs11' not found"];
        [self completeRow:removeRow success:NO summary:@"Skipped" detail:nil];
        [self completeRow:restartRow success:NO summary:@"Skipped" detail:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
          self.deregisterTokenButton.enabled = YES;
        });
        return;
      }

      [self completeRow:configRow
                success:YES
                summary:[NSString stringWithFormat:@"Found: %@", instanceID]
                 detail:nil];

      // 2. Remove token configuration (removes keychain items automatically)
      [self startRow:removeRow];
      [config removeTokenConfigurationForTokenInstanceID:instanceID];
      [self completeRow:removeRow
                success:YES
                summary:@"Token configuration removed"
                 detail:@"Keychain items cleared automatically"];

      // 3. Restart CTK daemon to apply changes
      [self startRow:restartRow];
      [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"ctkd" ]];
      sleep(1);
      [self completeRow:restartRow
                success:YES
                summary:@"CTK daemon restarted"
                 detail:nil];
    } else {
      [self completeRow:configRow
                success:NO
                summary:@"Requires macOS 10.15+"
                 detail:nil];
      [self completeRow:removeRow success:NO summary:@"Skipped" detail:nil];
      [self completeRow:restartRow success:NO summary:@"Skipped" detail:nil];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      self.deregisterTokenButton.enabled = YES;
    });
  });
}

/// Writes a JSON configuration file for the extension to Application Support.
/// Contains PKCS#11 module path, AID, and CTK class ID.
///
/// @param sender The button that triggered the action
- (IBAction)writeConfig:(id)sender {
  [self clearResults];
  NSUInteger configRow = [self addRowWithTitle:@"Write Config" waiting:NO];

  NSDictionary *config = @{
    @"modulePath" : [self pkcs11ModulePath] ?: @"",
    @"aid" : @"e828bd080fd25047656e65726963",
    @"ctkClassId" : @"com.andrei.rocei.connector.extension",
    @"note" : @"Generated by RO CEI Token Sanity Check"
  };

  NSError *error = nil;
  NSData *data =
      [NSJSONSerialization dataWithJSONObject:config
                                      options:NSJSONWritingPrettyPrinted
                                        error:&error];
  if (!data) {
    [self completeRow:configRow
              success:NO
              summary:@"Serialization failed"
               detail:error.localizedDescription];
    return;
  }

  NSURL *dir = [[[NSFileManager defaultManager]
      URLsForDirectory:NSApplicationSupportDirectory
             inDomains:NSUserDomainMask] firstObject];
  dir = [dir URLByAppendingPathComponent:@"com.andrei.rocei.connector.extension"
                             isDirectory:YES];
  [[NSFileManager defaultManager] createDirectoryAtURL:dir
                           withIntermediateDirectories:YES
                                            attributes:nil
                                                 error:nil];
  NSURL *file = [dir URLByAppendingPathComponent:@"config.json" isDirectory:NO];

  if (![data writeToURL:file options:NSDataWritingAtomic error:&error]) {
    [self completeRow:configRow
              success:NO
              summary:@"Write failed"
               detail:error.localizedDescription];
    return;
  }

  [self completeRow:configRow
            success:YES
            summary:file.path
             detail:[[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding]];
}

/// Kills the CryptoTokenKit daemon (ctkd) and PC/SC daemon
/// (com.apple.ctkpcscd), waits for them to restart, then verifies
/// the extension is still registered.
///
/// @param sender The button that triggered the action
- (IBAction)resetCTKDaemon:(id)sender {
  [self clearResults];
  self.resetCtkdButton.enabled = NO;

  NSUInteger ctkRow = [self addRowWithTitle:@"Stop CryptoTokenKit" waiting:NO];
  NSUInteger pcscRow = [self addRowWithTitle:@"Stop PC/SC Daemon" waiting:YES];
  NSUInteger waitRow = [self addRowWithTitle:@"Restart Services" waiting:YES];
  NSUInteger extRow = [self addRowWithTitle:@"Verify Extension" waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSString *r1 = [self runCommand:@"/usr/bin/killall"
                          arguments:@[ @"-9", @"ctkd" ]];
    [self completeRow:ctkRow success:YES summary:@"Stopped" detail:r1];

    [self startRow:pcscRow];
    NSString *r2 = [self runCommand:@"/usr/bin/killall"
                          arguments:@[ @"-9", @"com.apple.ctkpcscd" ]];
    [self completeRow:pcscRow success:YES summary:@"Stopped" detail:r2];

    [self startRow:waitRow];
    sleep(2);
    [self completeRow:waitRow
              success:YES
              summary:@"Services restarted"
               detail:nil];

    [self startRow:extRow];
    NSString *pluginkitOutput =
        [self runCommand:@"/usr/bin/pluginkit"
               arguments:@[ @"-m", @"-p", @"com.apple.ctk-tokens" ]];
    BOOL found = [pluginkitOutput
        containsString:@"com.andrei.rocei.connector.extension"];
    [self completeRow:extRow
              success:found
              summary:found ? @"Extension registered"
                            : @"Not found — try Re-register Extension"
               detail:pluginkitOutput];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.resetCtkdButton.enabled = YES;
    });
  });
}

#pragma mark - Troubleshooting Actions

/// Checks the extension bundle, PluginKit registration, CryptoTokenKit
/// token status, helper service, and leftover data from previous installs.
///
/// @param sender The button that triggered the action
- (IBAction)verifyInstallation:(id)sender {
  [self clearResults];
  self.verifyButton.enabled = NO;

  NSUInteger bundleRow = [self addRowWithTitle:@"Extension Bundle" waiting:NO];
  NSUInteger regRow = [self addRowWithTitle:@"Extension Registration"
                                    waiting:NO];
  NSUInteger tokenRow = [self addRowWithTitle:@"CryptoTokenKit Token"
                                      waiting:NO];
  NSUInteger helperRow = [self addRowWithTitle:@"Helper Service" waiting:NO];
  NSUInteger oldDataRow = [self addRowWithTitle:@"Old Token Data" waiting:NO];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // 1. Extension bundle
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    NSString *extensionPath =
        [appPath stringByAppendingPathComponent:
                     @"Contents/PlugIns/ROCEIExtension.appex"];
    BOOL extensionExists =
        [[NSFileManager defaultManager] fileExistsAtPath:extensionPath];
    [self
        completeRow:bundleRow
            success:extensionExists
            summary:extensionExists ? @"Found" : @"NOT found — rebuild the app"
             detail:extensionPath];

    // 2. Extension registration
    NSString *pluginkitOutput =
        [self runCommand:@"/usr/bin/pluginkit"
               arguments:@[ @"-m", @"-p", @"com.apple.ctk-tokens" ]];
    BOOL registered = [pluginkitOutput
        containsString:@"com.andrei.rocei.connector.extension"];
    [self
        completeRow:regRow
            success:registered
            summary:registered ? @"Registered with PluginKit"
                               : @"NOT registered — try Re-register or restart"
             detail:pluginkitOutput];

    // 3. CryptoTokenKit tokens
    NSArray<NSString *> *allTokenIDs = [self allTokenIDs];
    NSString *classID = @"com.andrei.rocei.connector.extension";
    BOOL tokenFound = NO;
    NSMutableString *tokenDetail = [NSMutableString string];
    for (NSString *tokenID in allTokenIDs) {
      if ([tokenID containsString:classID])
        tokenFound = YES;
      [tokenDetail appendFormat:@"%@\n", tokenID];
    }
    if (tokenFound) {
      [self completeRow:tokenRow
                success:YES
                summary:@"eID token registered"
                 detail:tokenDetail];
    } else {
      [self completeRow:tokenRow
                warning:@"Not registered — insert card and use Register Token"
                 detail:allTokenIDs.count > 0 ? tokenDetail : nil];
    }

    // 4. Helper service
    NSString *launchctlOutput = [self runCommand:@"/bin/launchctl"
                                       arguments:@[ @"list" ]];
    BOOL helperRunning =
        [launchctlOutput containsString:@"com.andrei.rocei.connector.helper"];
    [self completeRow:helperRow
              success:helperRunning
              summary:helperRunning ? @"Running"
                                    : @"Not running — relaunch the app"
               detail:nil];

    // 5. Old token data
    NSArray *oldPaths = @[
      [@"~/Library/Preferences/com.andrei.rocei.ROCEITokenApp.plist"
          stringByExpandingTildeInPath],
      [@"~/Library/Security/Tokens/"
       @"com.andrei.rocei.ROCEITokenApp.ROCEIToken.plist"
          stringByExpandingTildeInPath],
      [@"~/Applications/ROCEITokenApp.app" stringByExpandingTildeInPath],
      [@"/Applications/ROCEITokenApp.app" stringByExpandingTildeInPath]
    ];
    NSMutableString *oldDetail = [NSMutableString string];
    BOOL foundOld = NO;
    for (NSString *path in oldPaths) {
      if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [oldDetail appendFormat:@"Found: %@\n", path];
        foundOld = YES;
      }
    }
    if (foundOld) {
      [self completeRow:oldDataRow
                warning:@"Old data found — remove manually if needed"
                 detail:oldDetail];
    } else {
      [self completeRow:oldDataRow
                success:YES
                summary:@"Clean — no old data"
                 detail:nil];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
      self.verifyButton.enabled = YES;
    });
  });
}

/// Unregisters the extension via pluginkit -r, restarts ctkd, and
/// verifies the extension is no longer listed.
///
/// @param sender The button that triggered the action
- (IBAction)unregisterExtension:(id)sender {
  [self clearResults];
  self.unregisterButton.enabled = NO;

  NSUInteger unregRow = [self addRowWithTitle:@"Unregister Extension"
                                      waiting:NO];
  NSUInteger restartRow = [self addRowWithTitle:@"Restart Services"
                                        waiting:YES];
  NSUInteger verifyRow = [self addRowWithTitle:@"Verify Unregistered"
                                       waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSString *appPath = [[NSBundle mainBundle] bundlePath];

    NSString *r1 = [self runCommand:@"/usr/bin/pluginkit"
                          arguments:@[ @"-r", appPath ]];
    [self completeRow:unregRow success:YES summary:@"Unregistered" detail:r1];

    [self startRow:restartRow];
    [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"pluginkit" ]];
    [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"ctkd" ]];
    sleep(1);
    [self completeRow:restartRow
              success:YES
              summary:@"Services restarted"
               detail:nil];

    [self startRow:verifyRow];
    NSString *pluginkitOutput =
        [self runCommand:@"/usr/bin/pluginkit"
               arguments:@[ @"-m", @"-p", @"com.apple.ctk-tokens" ]];
    BOOL found = [pluginkitOutput
        containsString:@"com.andrei.rocei.connector.extension"];
    [self completeRow:verifyRow
              success:!found
              summary:found ? @"Still registered — restart Mac to complete"
                            : @"Extension unregistered"
               detail:pluginkitOutput];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.unregisterButton.enabled = YES;
    });
  });
}

/// Re-registers the extension via pluginkit -a, restarts services,
/// and verifies it appears in the CTK tokens list.
///
/// @param sender The button that triggered the action
- (IBAction)registerExtension:(id)sender {
  [self clearResults];
  self.registerExtButton.enabled = NO;

  NSUInteger regRow = [self addRowWithTitle:@"Register Extension" waiting:NO];
  NSUInteger restartRow = [self addRowWithTitle:@"Restart Services"
                                        waiting:YES];
  NSUInteger verifyRow = [self addRowWithTitle:@"Verify Registered"
                                       waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSString *appPath = [[NSBundle mainBundle] bundlePath];

    [self runCommand:@"/usr/bin/pluginkit" arguments:@[ @"-a", appPath ]];
    [self completeRow:regRow success:YES summary:@"Registered" detail:nil];

    [self startRow:restartRow];
    [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"pluginkit" ]];
    [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"ctkd" ]];
    sleep(1);
    [self completeRow:restartRow
              success:YES
              summary:@"Services restarted"
               detail:nil];

    [self startRow:verifyRow];
    NSString *pluginkitOutput =
        [self runCommand:@"/usr/bin/pluginkit"
               arguments:@[ @"-m", @"-p", @"com.apple.ctk-tokens" ]];
    BOOL found = [pluginkitOutput
        containsString:@"com.andrei.rocei.connector.extension"];
    [self completeRow:verifyRow
              success:found
              summary:found ? @"Extension registered"
                            : @"Not found — try restarting Mac"
               detail:pluginkitOutput];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.registerExtButton.enabled = YES;
    });
  });
}

/// Full uninstall: deregisters the token, unregisters the extension from
/// PluginKit, unregisters the helper LaunchAgent, kills related daemons,
/// closes the XPC connection, moves the app to trash, and terminates.
///
/// @param sender The button that triggered the action
- (IBAction)uninstallApp:(id)sender {
  NSAlert *alert = [[NSAlert alloc] init];
  alert.messageText = @"Uninstall RO CEI Connector?";
  alert.informativeText =
      @"This will:\n"
      @"\u2022 Deregister the eID token from CryptoTokenKit\n"
      @"\u2022 Unregister the CryptoTokenKit extension\n"
      @"\u2022 Unregister the XPC helper service\n"
      @"\u2022 Move the app to Trash\n"
      @"\u2022 Quit the app\n\n"
      @"This cannot be undone.";
  [alert addButtonWithTitle:@"Uninstall"];
  [alert addButtonWithTitle:@"Cancel"];
  alert.alertStyle = NSAlertStyleCritical;

  // Make the Uninstall button red/destructive
  alert.buttons.firstObject.hasDestructiveAction = YES;

  if ([alert runModal] != NSAlertFirstButtonReturn) {
    return;
  }

  [self clearResults];
  self.uninstallButton.enabled = NO;

  NSUInteger tokenRow = [self addRowWithTitle:@"Deregister Token" waiting:NO];
  NSUInteger extensionRow = [self addRowWithTitle:@"Unregister Extension"
                                           waiting:YES];
  NSUInteger helperRow = [self addRowWithTitle:@"Unregister Helper"
                                       waiting:YES];
  NSUInteger cleanupRow = [self addRowWithTitle:@"Cleanup" waiting:YES];
  NSUInteger trashRow = [self addRowWithTitle:@"Move to Trash" waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // 1. Deregister token
    if (@available(macOS 10.15, *)) {
      NSDictionary<TKTokenDriverClassID, TKTokenDriverConfiguration *>
          *configs = TKTokenDriverConfiguration.driverConfigurations;
      TKTokenDriverConfiguration *config =
          configs[@"com.andrei.rocei.connector.extension"];
      NSString *instanceID = @"rocei-pkcs11";

      if (config && config.tokenConfigurations[instanceID]) {
        [config removeTokenConfigurationForTokenInstanceID:instanceID];
        [self completeRow:tokenRow
                  success:YES
                  summary:@"Token deregistered"
                   detail:nil];
      } else {
        [self completeRow:tokenRow
                  success:YES
                  summary:@"No token registered"
                   detail:nil];
      }
    } else {
      [self completeRow:tokenRow
                success:YES
                summary:@"Skipped (macOS 10.15+)"
                 detail:nil];
    }

    // 2. Unregister extension from PluginKit
    [self startRow:extensionRow];
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    [self runCommand:@"/usr/bin/pluginkit" arguments:@[ @"-r", appPath ]];
    [self runCommand:@"/usr/bin/killall" arguments:@[ @"-9", @"ctkd" ]];
    [self completeRow:extensionRow
              success:YES
              summary:@"Extension unregistered"
               detail:nil];

    // 3. Unregister helper LaunchAgent
    [self startRow:helperRow];
    @try {
      // Invalidate XPC connection first
      [self.helperConnection invalidate];
      @synchronized(self) {
        self.helperConnection = nil;
      }

      // Unregister the agent via SMAppService
      SMAppService *service = [SMAppService
          agentServiceWithPlistName:
              @"com.andrei.rocei.connector.helper.plist"];
      NSError *unreg = nil;
      if ([service unregisterAndReturnError:&unreg]) {
        [self completeRow:helperRow
                  success:YES
                  summary:@"Helper unregistered"
                   detail:nil];
      } else {
        [self completeRow:helperRow
                  success:NO
                  summary:@"Unregister failed"
                   detail:unreg.localizedDescription];
      }
    } @catch (NSException *e) {
      [self completeRow:helperRow
                success:NO
                summary:@"Exception"
                 detail:e.reason];
    }

    // 4. Kill related processes, clean up certs
    [self startRow:cleanupRow];
    [self runCommand:@"/usr/bin/pkill"
           arguments:@[ @"-9", @"pkcs11-tool" ]
      timeoutSeconds:5];
    [self runCommand:@"/usr/bin/killall"
           arguments:@[ @"-9", @"pluginkit" ]];

    // Remove cached certificate files from extension container
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *containerURLs = [fm URLsForDirectory:NSLibraryDirectory
                                        inDomains:NSUserDomainMask];
    if (containerURLs.count > 0) {
      NSURL *containerURL = [containerURLs[0]
          URLByAppendingPathComponent:
              @"Containers/com.andrei.rocei.connector.extension/Data"];
      for (NSString *f in @[
             @"auth_cert.der", @"sign_cert.der", @"auth_keyid.bin"
           ]) {
        [fm removeItemAtPath:
                [containerURL URLByAppendingPathComponent:f].path
                       error:nil];
      }
    }
    [self completeRow:cleanupRow
              success:YES
              summary:@"Processes killed, certs cleared"
               detail:nil];

    // 5. Move app to Trash
    [self startRow:trashRow];
    NSURL *appURL = [NSURL fileURLWithPath:appPath];
    NSURL *trashedURL = nil;
    NSError *trashError = nil;
    BOOL trashed = [fm trashItemAtURL:appURL
                     resultingItemURL:&trashedURL
                                error:&trashError];
    if (trashed) {
      [self completeRow:trashRow
                success:YES
                summary:@"Moved to Trash"
                 detail:trashedURL.path];
    } else {
      [self completeRow:trashRow
                success:NO
                summary:@"Could not move to Trash"
                 detail:trashError.localizedDescription];
    }

    // Give the UI a moment to render final status, then quit
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          [NSApp terminate:nil];
        });
  });
}

/// Kills all pkcs11-tool processes using pkill -9.
///
/// @param sender The button that triggered the action
- (IBAction)killPkcs11Processes:(id)sender {
  [self clearResults];
  self.killPkcs11Button.enabled = NO;

  NSUInteger row = [self addRowWithTitle:@"Kill pkcs11-tool Processes"
                                 waiting:NO];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // Find and kill all pkcs11-tool processes
    NSString *output = [self runCommand:@"/usr/bin/pkill"
                              arguments:@[ @"-9", @"pkcs11-tool" ]
                         timeoutSeconds:5];

    // Check if any processes were killed
    BOOL success = ![output containsString:@"ERROR"];
    NSString *summary = success ? @"All pkcs11-tool processes terminated"
                                : @"Failed to kill processes";

    [self completeRow:row success:success summary:summary detail:output];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.killPkcs11Button.enabled = YES;
    });
  });
}

/// Full PKCS#11 reset: closes sessions (C_Finalize), kills pkcs11-tool
/// processes, and clears cached certificates.
/// Shows a confirmation dialog before proceeding.
///
/// @param sender The button that triggered the action
- (IBAction)resetPKCS11:(id)sender {
  // Show confirmation alert since this is destructive
  NSAlert *alert = [[NSAlert alloc] init];
  alert.messageText = @"Reset PKCS#11?";
  alert.informativeText =
      @"This will:\n• Close all open PKCS#11 sessions (C_Finalize)\n• Kill all "
      @"pkcs11-tool processes\n• Clear cached certificates\n\nContinue?";
  [alert addButtonWithTitle:@"Reset"];
  [alert addButtonWithTitle:@"Cancel"];
  alert.alertStyle = NSAlertStyleWarning;

  NSModalResponse response = [alert runModal];
  if (response != NSAlertFirstButtonReturn) {
    return; // User cancelled
  }

  [self clearResults];
  self.resetPKCS11Button.enabled = NO;

  NSUInteger finalizeRow = [self addRowWithTitle:@"Close Sessions" waiting:NO];
  NSUInteger killRow = [self addRowWithTitle:@"Kill Processes" waiting:YES];
  NSUInteger certRow = [self addRowWithTitle:@"Clear Cached Certs" waiting:YES];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    // 1. Tell the helper to C_Finalize (closes all hanging PKCS#11 sessions)
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __weak dispatch_semaphore_t weakSem = sem;
    __block BOOL resetOK = NO;
    __block NSString *resetMsg = @"Timed out waiting for helper";
    @try {
      NSXPCConnection *connection = [self helperConnection];
      id<ROCEISigningServiceProtocol> helper =
          [connection remoteObjectProxyWithErrorHandler:^(NSError *xpcError) {
            resetMsg =
                [NSString stringWithFormat:@"XPC error: %@",
                                           xpcError.localizedDescription];
            dispatch_semaphore_t strongSem = weakSem;
            if (strongSem) {
              dispatch_semaphore_signal(strongSem);
            }
          }];
      [helper resetPKCS11WithReply:^(BOOL success, NSString *message) {
        resetOK = success;
        resetMsg = message;
        dispatch_semaphore_t strongSem = weakSem;
        if (strongSem) {
          dispatch_semaphore_signal(strongSem);
        }
      }];
      dispatch_semaphore_wait(
          sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    } @catch (NSException *e) {
      resetMsg = [NSString stringWithFormat:@"Exception: %@", e.reason];
    }
    if (resetOK) {
      [self completeRow:finalizeRow
                success:YES
                summary:@"C_Finalize OK — sessions closed"
                 detail:resetMsg];
    } else {
      // Helper not running means no sessions to close — that's fine
      [self completeRow:finalizeRow
                warning:@"Helper not running (no sessions to close)"
                 detail:resetMsg];
    }

    // 2. Kill pkcs11-tool processes
    [self startRow:killRow];
    NSString *killOutput = [self runCommand:@"/usr/bin/pkill"
                                  arguments:@[ @"-9", @"pkcs11-tool" ]
                             timeoutSeconds:5];
    BOOL killHasError = [killOutput containsString:@"error"] ||
                        [killOutput containsString:@"Error"];
    [self completeRow:killRow
              success:!killHasError
              summary:killHasError ? @"Failed" : @"Done"
               detail:killOutput];

    // 3. Clear cached certificate files from extension container
    [self startRow:certRow];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableString *certDetail = [NSMutableString string];
    BOOL certOK = YES;
    NSArray *containerURLs = [fm URLsForDirectory:NSLibraryDirectory
                                        inDomains:NSUserDomainMask];
    NSUInteger certsRemoved = 0;
    if (containerURLs.count > 0) {
      NSURL *containerURL = [containerURLs[0]
          URLByAppendingPathComponent:
              @"Containers/com.andrei.rocei.connector.extension/Data"];
      NSArray *certFiles =
          @[ @"auth_cert.der", @"sign_cert.der", @"auth_keyid.bin" ];

      for (NSString *certFile in certFiles) {
        NSURL *certURL = [containerURL URLByAppendingPathComponent:certFile];
        if ([fm fileExistsAtPath:certURL.path]) {
          NSError *certError = nil;
          if ([fm removeItemAtURL:certURL error:&certError]) {
            [certDetail appendFormat:@"Removed %@\n", certFile];
            certsRemoved++;
          } else {
            [certDetail appendFormat:@"Failed to remove %@: %@\n", certFile,
                                     certError.localizedDescription];
            certOK = NO;
          }
        }
      }
    }
    NSString *certSummary;
    if (certsRemoved > 0) {
      certSummary = [NSString stringWithFormat:@"%lu file%@ removed",
                                               (unsigned long)certsRemoved,
                                               certsRemoved == 1 ? @"" : @"s"];
    } else {
      certSummary = certOK ? @"Already clean" : @"Failed";
    }
    [self completeRow:certRow
              success:certOK
              summary:certSummary
               detail:certDetail.length > 0 ? certDetail
                                            : @"No cached files found"];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.resetPKCS11Button.enabled = YES;
    });
  });
}

/// Displays extension details: app bundle path, embedded .appex Info.plist
/// metadata (bundle ID, version, driver class), and registered CTK
/// extensions from pluginkit.
///
/// @param sender The button that triggered the action
- (IBAction)showExtensionInfo:(id)sender {
  [self clearResults];
  self.extensionInfoButton.enabled = NO;

  NSUInteger bundleRow = [self addRowWithTitle:@"App Bundle" waiting:NO];
  NSUInteger extRow = [self addRowWithTitle:@"Extension Details" waiting:NO];
  NSUInteger regRow = [self addRowWithTitle:@"Registered CTK Extensions"
                                    waiting:NO];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    NSString *appPath = [[NSBundle mainBundle] bundlePath];
    NSString *extensionPath =
        [appPath stringByAppendingPathComponent:
                     @"Contents/PlugIns/ROCEIExtension.appex"];

    [self completeRow:bundleRow success:YES summary:appPath detail:nil];

    BOOL extensionExists =
        [[NSFileManager defaultManager] fileExistsAtPath:extensionPath];
    if (extensionExists) {
      NSMutableString *detail = [NSMutableString string];
      NSString *infoPlistPath =
          [extensionPath stringByAppendingPathComponent:@"Contents/Info.plist"];
      NSDictionary *info =
          [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
      NSString *summary = @"Embedded";
      if (info) {
        NSString *bundleID = info[@"CFBundleIdentifier"] ?: @"?";
        NSString *version = [NSString
            stringWithFormat:@"%@ (%@)",
                             info[@"CFBundleShortVersionString"] ?: @"?",
                             info[@"CFBundleVersion"] ?: @"?"];
        summary = [NSString stringWithFormat:@"%@ v%@", bundleID, version];
        [detail appendFormat:@"Bundle ID: %@\n", bundleID];
        [detail appendFormat:@"Version: %@\n", version];
        NSDictionary *extPoint = info[@"NSExtension"];
        if (extPoint) {
          [detail appendFormat:@"Extension Point: %@\n",
                               extPoint[@"NSExtensionPointIdentifier"] ?: @"?"];
          NSDictionary *attrs = extPoint[@"NSExtensionAttributes"];
          if (attrs) {
            [detail appendFormat:@"Driver Class: %@\n",
                                 attrs[@"TKTokenDriverClassID"] ?: @"?"];
          }
        }
      }
      [self completeRow:extRow success:YES summary:summary detail:detail];
    } else {
      [self completeRow:extRow
                success:NO
                summary:@"Extension not found in bundle"
                 detail:extensionPath];
    }

    NSString *pluginkitOutput =
        [self runCommand:@"/usr/bin/pluginkit"
               arguments:@[ @"-m", @"-v", @"-p", @"com.apple.ctk-tokens" ]];
    BOOL hasOurs = [pluginkitOutput
        containsString:@"com.andrei.rocei.connector.extension"];
    NSUInteger extCount = 0;
    for (NSString *line in
         [pluginkitOutput componentsSeparatedByString:@"\n"]) {
      NSString *t =
          [line stringByTrimmingCharactersInSet:[NSCharacterSet
                                                    whitespaceCharacterSet]];
      if (t.length > 0 && ![t containsString:@"plug-ins"])
        extCount++;
    }
    [self completeRow:regRow
              success:hasOurs
              summary:[NSString stringWithFormat:@"%lu extension%@%@",
                                                 (unsigned long)extCount,
                                                 extCount == 1 ? @"" : @"s",
                                                 hasOurs ? @" (ours found)"
                                                         : @" (ours missing)"]
               detail:pluginkitOutput];

    dispatch_async(dispatch_get_main_queue(), ^{
      self.extensionInfoButton.enabled = YES;
    });
  });
}

@end
