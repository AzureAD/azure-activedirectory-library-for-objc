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

#import "ADAuthenticationDelegate.h"
#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationWindowController.h"

@interface ADAuthenticationWindowController () <ADAuthenticationDelegate>
@end

@implementation ADAuthenticationWindowController
{
    IBOutlet WebView *_webView;
    
    ADAuthenticationWebViewController*  _webViewController;
    id                                  _webViewResourceLoadDelegate;
    
    BOOL      _complete;
    BOOL      _closed;
    
    NSURL    *_startURL;
    NSURL    *_endURL;

    // Counter for load/finish of webview requests
    __volatile int32_t _loadCounter;
}

@synthesize delegate = _delegate;

#pragma mark - Initialization

// Initialization
- (id)initAtURL:(NSURL *)startURL endAtURL:(NSURL *)endURL
{
    self = [super initWithWindowNibName:@"ADAuthenticationWindowController"];
    if ( self )
    {
        _startURL    = [startURL copy];
        _endURL      = [endURL copy];
        
        _complete    = NO; // Not complete
        _closed      = NO; // Not closed
        _loadCounter = 0;
        
        _webViewController           = nil;
        _webViewResourceLoadDelegate = nil;
    }
    
    return self;
}

// Debug logging only
- (void)dealloc
{
    _webViewController           = nil;
    _webViewResourceLoadDelegate = nil;
}

#pragma mark - Public Methods

- (void)start
{
    [_webViewController start];
}

#pragma mark - Private Methods

- (void)onStartActivityIndicator:(id)sender
{
#pragma unused(sender)
    
    if ( _loadCounter > 0 )
    {
        [_progressIndicator startAnimation:nil];
        [_progressIndicator setHidden:NO];
    }
}

#pragma mark - NSWindowController

- (void)showWindow:(id)sender
{
    // Center the window like an alert
    [[self window] center];
    
    [super showWindow:sender];
    
    [_webViewController start];
}

- (void)windowDidLoad
{
    // Become the delegate for the window
    self.window.delegate = self;
    
    // Hide the progress indicator
    [_progressIndicator setHidden:YES];
    
    // Create the WebView Controller
    _webViewController = [[ADAuthenticationWebViewController alloc] initWithWebView:_webView startAtURL:_startURL endAtURL:_endURL];
    _webViewController.delegate         = self;
    
    // Now we steal the FrameLoadDelegate from the WebView but will forward events to the old delegate.
    // Forwarding has to be cautious since the FrameLoadDelegate is an informal protocol and the old
    // delegate may not have implemented all the methods.
    _webViewResourceLoadDelegate  = _webView.resourceLoadDelegate;
    _webView.resourceLoadDelegate = self;
}

- (void)windowWillLoad
{
    // Intentionally empty
}

#pragma mark - NSWindowDelegate methods

- (void)windowWillClose:(NSNotification *)notification
{
#pragma unused(notification)
    
    if ( !_complete && !_closed )
    {
        // NOTE: The _closed flag is used because when this window is run modal,
        //       the synchronous call to the delegate will end the modal session
        //       and that will cause this method to be re-entered and we will enter
        //       a loop. The delegate call cannot be async as it will not get
        //       dispatched while we are in the modal session.
        _closed = YES;
        
        [_webViewController stop];
        
        NSAssert( nil != _delegate, @"Delegate has been lost" );
        [_delegate webAuthenticationDidCancel];
    }
}

#pragma mark - WebResourceLoadDelegate

// All of these methods are forwarded to the original delegate, we use only two methods to control the
// progress indicator on the window.

- (id)webView:(WebView *)sender identifierForInitialRequest:(NSURLRequest *)request fromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        return [_webViewResourceLoadDelegate webView:sender identifierForInitialRequest:request fromDataSource:dataSource];
    else
        return request.URL;
}

- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource
{
    // Start and show the progress indicator, provided that this is not a redirect
    // that resulted from a previous request.
    if ( !redirectResponse )
    {
        OSAtomicIncrement32( &_loadCounter );
        
        [NSTimer scheduledTimerWithTimeInterval:1.0
                                         target:self
                                       selector:@selector(onStartActivityIndicator:)
                                       userInfo:nil
                                        repeats:NO];
    }
    
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        return [_webViewResourceLoadDelegate webView:sender resource:identifier willSendRequest:request redirectResponse:redirectResponse fromDataSource:dataSource];
    else
        return request;
}

- (void)webView:(WebView *)sender resource:(id)identifier didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge fromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didReceiveAuthenticationChallenge:challenge fromDataSource:dataSource];
}

- (void)webView:(WebView *)sender resource:(id)identifier didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge fromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didCancelAuthenticationChallenge:challenge fromDataSource:dataSource];
}

- (void)webView:(WebView *)sender resource:(id)identifier didReceiveResponse:(NSURLResponse *)response fromDataSource:(WebDataSource *)dataSource
{
    if ( OSAtomicDecrement32( &_loadCounter ) == 0 )
    {
        // Stop and hide the progress indicator
        [_progressIndicator stopAnimation:nil];
        [_progressIndicator setHidden:YES];
    }
    
    NSAssert( _loadCounter >= 0, @"WebView load/finsh unbalanced" );
    
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didReceiveResponse:response fromDataSource:dataSource];
}

- (void)webView:(WebView *)sender resource:(id)identifier didReceiveContentLength:(NSInteger)length fromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didReceiveContentLength:length fromDataSource:dataSource];
}

- (void)webView:(WebView *)sender resource:(id)identifier didFinishLoadingFromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didFinishLoadingFromDataSource:dataSource];
}

- (void)webView:(WebView *)sender resource:(id)identifier didFailLoadingWithError:(NSError *)error fromDataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender resource:identifier didFailLoadingWithError:error fromDataSource:dataSource];
}

- (void)webView:(WebView *)sender plugInFailedWithError:(NSError *)error dataSource:(WebDataSource *)dataSource
{
    if ( _webViewResourceLoadDelegate && [_webViewResourceLoadDelegate respondsToSelector:_cmd] )
        [_webViewResourceLoadDelegate webView:sender plugInFailedWithError:error dataSource:dataSource];
}

#pragma mark - WebAuthenticationDelegate

// The following methods are called on the main thread from the WebAuthenticationWebViewController.
// They are forwarded synchronously to the WebAuthenticationBroker that is listening as our delegate.
- (void)webAuthenticationDidCancel
{
    NSAssert( nil != _delegate, @"Delegate has been lost" );
    [_delegate webAuthenticationDidCancel];
}

- (void)webAuthenticationDidCompleteWithURL:(NSURL *)endURL
{
    _complete = YES;
    
    NSAssert( nil != _delegate, @"Delegate has been lost" );
    [_delegate webAuthenticationDidCompleteWithURL:endURL];
}

- (void)webAuthenticationDidFailWithError:(NSError *)error
{
    _complete = YES;
    
    NSAssert( nil != _delegate, @"Delegate has been lost" );
    [_delegate webAuthenticationDidFailWithError:error];
}

@end
