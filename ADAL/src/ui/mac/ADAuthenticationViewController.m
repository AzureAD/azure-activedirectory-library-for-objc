// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADWebAuthDelegate.h"
#import "ADAuthenticationViewController.h"
#import "ADLogger.h"
#import "ADALFrameworkUtils.h"

#define DEFAULT_WINDOW_WIDTH 420
#define DEFAULT_WINDOW_HEIGHT 650

static NSRect _CenterRect(NSRect rect1, NSRect rect2)
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
    __weak id<ADWebAuthDelegate> _delegate;
    WebViewType* _webView;
    NSProgressIndicator* _progressIndicator;
}

@end

@implementation ADAuthenticationViewController

@synthesize webView = _webView;
@synthesize delegate = _delegate;

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
    [window setAccessibilityIdentifier:@"ADAL_SIGN_IN_WINDOW"];

    
    
    NSView* contentView = window.contentView;
    [contentView setAutoresizesSubviews:YES];
    
    WebView* webView = [[WebView alloc] initWithFrame:contentView.frame];
    [webView setFrameLoadDelegate:self];
    [webView setResourceLoadDelegate:self];
    [webView setPolicyDelegate:self];
    [webView setAutoresizingMask:NSViewHeightSizable | NSViewWidthSizable];
    [webView setAccessibilityIdentifier:@"ADAL_SIGN_IN_WEBVIEW"];

    [contentView addSubview:webView];
    
    NSProgressIndicator* progressIndicator = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(DEFAULT_WINDOW_WIDTH / 2 - 16, DEFAULT_WINDOW_HEIGHT / 2 - 16, 32, 32)];
    [progressIndicator setStyle:NSProgressIndicatorSpinningStyle];
    // Keep the item centered in the window even if it's resized.
    [progressIndicator setAutoresizingMask:NSViewMinXMargin | NSViewMaxXMargin | NSViewMinYMargin | NSViewMaxYMargin];
    
    // On OS X there's a noticable lag between the window showing and the page loading, so starting with the spinner
    // at least make it looks like something is happening.
    [progressIndicator setHidden:NO];
    [progressIndicator startAnimation:nil];
    
    [contentView addSubview:progressIndicator];
    _progressIndicator = progressIndicator;
    
    _webView = webView;
    self.window = window;
    
    return YES;
}

- (void)dealloc
{
    [_webView setFrameLoadDelegate:nil];
    [_webView setResourceLoadDelegate:nil];
    [_webView setPolicyDelegate:nil];
    _webView = nil;
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

- (void)loadRequest:(NSURLRequest *)request
{
    [_webView.mainFrame loadRequest:request];
}

- (void)startSpinner
{
    [_progressIndicator setHidden:NO];
    [_progressIndicator startAnimation:nil];
    [self.window.contentView setNeedsDisplay:YES];
}

- (void)webView:(WebView *)webView
decidePolicyForNavigationAction:(NSDictionary *)actionInformation
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
