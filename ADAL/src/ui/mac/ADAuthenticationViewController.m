// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADWebAuthDelegate.h"
#import "ADAuthenticationViewController.h"
#import "ADLogger.h"
#import "ADALFrameworkUtils.h"

#define DEFAULT_WINDOW_WIDTH 420
#define DEFAULT_WINDOW_HEIGHT 650

static CGRect _CenterRect(CGRect rect1, CGRect rect2)
{
    CGFloat x = rect1.origin.x + ((rect1.size.width - rect2.size.width) / 2);
    CGFloat y = rect1.origin.y + ((rect1.size.height - rect2.size.height) / 2);
    
    x = x < 0 ? 0 : x;
    y = y < 0 ? 0 : y;
    
    rect2.origin.x = x;
    rect2.origin.y = y;
    
    return rect2;
}


@interface ADAuthenticationViewController ( ) <WebResourceLoadDelegate, WebPolicyDelegate, WebFrameLoadDelegate, NSWindowDelegate>
{
    __weak NSProgressIndicator* _progressIndicator;
}

@end

@implementation ADAuthenticationViewController

- (void)loadView
{
    [self loadView:nil];
}

- (BOOL)loadView:(ADAuthenticationError * __autoreleasing *)error
{
    (void)error;
    
    if (_webView)
    {
        [_webView setFrameLoadDelegate:self];
        [_webView setResourceLoadDelegate:self];
        [_webView setPolicyDelegate:self];
        
        return YES;
    }
    
    NSWindow* mainWindow = [NSApp mainWindow];
    NSRect windowRect;
    if (mainWindow)
    {
        windowRect = mainWindow.frame;
    }
    else
    {
        // If we didn't get a main window then center it in the screen
        windowRect = [[NSScreen mainScreen] frame];
    }
    
    // Calculate the center of the current main window so we can position our window in the center of it
    NSRect centerRect = _CenterRect(windowRect, NSMakeRect(0, 0, DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT));
    
    NSWindow* window = [[NSWindow alloc] initWithContentRect:centerRect
                                                   styleMask:NSTitledWindowMask | NSClosableWindowMask
                                                     backing:NSBackingStoreBuffered
                                                       defer:YES];
    [window setDelegate:self];
    
    
    
    NSView* contentView = window.contentView;
    [contentView setAutoresizesSubviews:YES];
    
    WebView* webView = [[WebView alloc] initWithFrame:contentView.frame];
    [webView setFrameLoadDelegate:self];
    [webView setResourceLoadDelegate:self];
    [webView setPolicyDelegate:self];
    [webView setAutoresizingMask:NSViewHeightSizable | NSViewWidthSizable];
    
    [contentView addSubview:webView];
    
    NSProgressIndicator* progressIndicator = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(DEFAULT_WINDOW_WIDTH / 2 - 16, DEFAULT_WINDOW_HEIGHT / 2 - 16, 32, 32)];
    [progressIndicator setStyle:NSProgressIndicatorSpinningStyle];
    // Keep the item centered in the window even if it's resized.
    [progressIndicator setAutoresizingMask:NSViewMinXMargin | NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin];
    
    // On OS X there's a noticable lag between the window showing and the page loading, so starting with the spinner
    // at least make it looks liek something is happening.
    [progressIndicator setHidden:NO];
    [progressIndicator startAnimation:nil];
    
    [contentView addSubview:progressIndicator];
    _progressIndicator = progressIndicator;
    
    _webView = webView;
    self.window = window;
    
    return YES;
}

#pragma mark - UIViewController Methods

#pragma mark - Event Handlers

// Authentication was cancelled by the user by closing the window
- (void)windowWillClose:(NSNotification *)notification
{
    (void)notification;
    
    [_delegate webAuthDidCancel];
}

// Fired 2 seconds after a page loads starts to show waiting indicator

- (void)stop:(void (^)(void))completion
{
    [_webView.mainFrame stopLoading];
    _delegate = nil;
    [self close];
    completion();
}

- (void)startRequest:(NSURLRequest *)request
{
    [self showWindow:nil];
    [self loadRequest:request];
}

- (void)loadRequest:(NSURLRequest*)request
{
    [_webView.mainFrame loadRequest:request];
}

- (void)startSpinner
{
    [_progressIndicator setHidden:NO];
    [_progressIndicator startAnimation:nil];
    [self.window.contentView setNeedsDisplay:YES];
}

- (void)webView:(WebView *)webView decidePolicyForNavigationAction:(NSDictionary *)actionInformation
        request:(NSURLRequest *)request
          frame:(WebFrame *)frame
decisionListener:(id<WebPolicyDecisionListener>)listener
{
    (void)webView;
    (void)actionInformation;
    (void)frame;
    
    if ([_delegate webAuthShouldStartLoadRequest:request])
    {
        [listener use];
        [_delegate webAuthDidStartLoad:request.URL];
    }
    else
    {
        [listener ignore];
    }
}

- (void)webView:(WebView *)sender resource:(id)identifier didFinishLoadingFromDataSource:(WebDataSource *)dataSource
{
    (void)sender;
    (void)identifier;
    (void)dataSource;
    
    [_delegate webAuthDidFinishLoad:dataSource.request.URL];
}

- (void)stopSpinner
{
    [_progressIndicator setHidden:YES];
    [_progressIndicator stopAnimation:nil];
}


- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    (void)sender;
    (void)frame;
    [_delegate webAuthDidFailWithError:error];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
    (void)sender;
    (void)frame;
    [_delegate webAuthDidFailWithError:error];
}

@end
