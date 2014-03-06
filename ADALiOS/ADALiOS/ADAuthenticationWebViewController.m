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

@implementation ADAuthenticationWebViewController
{
    __weak WebViewType *_webView;
    
    NSURL    *_startURL;
    NSString *_endURL;
    BOOL      _complete;
}

#pragma mark - Initialization

- (id)initWithWebView:(WebViewType *)webView startAtURL:(NSURL *)startURL endAtURL:(NSURL *)endURL
{
    if ( nil == startURL || nil == endURL )
        return nil;
    
    if ( nil == webView )
        return nil;
    
    if ( ( self = [super init] ) != nil )
    {
        _startURL  = [startURL copy];
        _endURL    = [[endURL absoluteString] lowercaseString];
        
        _complete  = NO;
        
        _webView          = webView;
#if TARGET_OS_IPHONE
        _webView.delegate = self;
#else
        _delegate = nil;
#endif
    }
    
    return self;
}

@synthesize delegate  = _delegate;

- (void)dealloc
{
    // The ADAuthenticationWebViewController can be released before the
    // UIWebView that it is managing is released in the hosted case and
    // so it is important that to stop listening for events from the
    // UIWebView when we are released.
#if TARGET_OS_IPHONE
    _webView.delegate = nil;
#else
    _webView.frameLoadDelegate    = nil;
    _webView.resourceLoadDelegate = nil;
    _webView.policyDelegate       = nil;
#endif
    _webView          = nil;
}

#pragma mark - Public Methods

- (void)start
{
    NSURLRequest *request = [NSURLRequest requestWithURL:_startURL];

#if TARGET_OS_IPHONE
    [_webView loadRequest:request];
#else
    // Start the authentication process
    [_webView.mainFrame loadRequest:request];
#endif
}

- (void)stop
{
    //In future this method may be expanded to clear some state like cookies
}

#pragma mark - UIWebViewDelegate Protocol

#if TARGET_OS_IPHONE
- (BOOL)webView:(WebViewType *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType
{
#pragma unused(webView)
#pragma unused(navigationType)
    
    //DebugLog( @"URL: %@", request.URL.absoluteString );
    
    // TODO: We lowercase both URLs, is this the right thing to do?
    NSString *requestURL = [[request.URL absoluteString] lowercaseString];
    
    // Stop at the end URL.
    if ( [requestURL hasPrefix:_endURL] )
    {
        // iOS generates a 102, Frame load interrupted error from stopLoading, so we set a flag
        // here to note that it was this code that halted the frame load in order that we can ignore
        // the error when we are notified later.
        _complete = YES;
        
        // Schedule the finish event; we do this so that the web view gets a chance to stop
        // This event is explicitly scheduled on the main thread as it is UI related.
        NSAssert( nil != _delegate, @"Delegate object was lost" );
        dispatch_async( dispatch_get_main_queue(), ^{ [_delegate webAuthenticationDidCompleteWithURL:request.URL]; } );
        
        // Tell the web view that this URL should not be loaded.
        return NO;
    }
    
    return YES;
}
#endif //TARGET_OS_IPHONE

#if TARGET_OS_IPHONE
- (void)webViewDidStartLoad:(UIWebView *)webView
{
#pragma unused(webView)
}
#endif//TARGET_OS_IPHONE

#if TARGET_OS_IPHONE
- (void)webViewDidFinishLoad:(UIWebView *)webView
{
#pragma unused(webView)
}
#endif//TARGET_OS_IPHONE

-(void) dispatchError: (NSError*) error
{
    AD_LOG_WARN(@"authorization error", [error localizedDescription]);
    
    // Tell our delegate that we are done after an error.
    if (_delegate)
    {
#if TARGET_OS_IPHONE
        //On iOS, enque on the main thread:
        dispatch_async( dispatch_get_main_queue(), ^{ [_delegate webAuthenticationDidFailWithError:error]; } );
#else
        [self.delegate webAuthenticationDidFailWithError:error];
#endif
    }
    else
    {
        AD_LOG_ERROR(@"Delegate object is lost", AD_ERROR_APPLICATION, @"The delegate object was lost, potentially due to another concurrent request.");
    }
}

#if (TARGET_OS_IPHONE)
- (void)webView:(WebViewType *)webView didFailLoadWithError:(NSError *)error
{
#pragma unused(webView)
    
    if (NSURLErrorCancelled == error.code)
    {
        //This is a common error that webview generates and could be ignored.
        //See this thread for details: https://discussions.apple.com/thread/1727260
        return;
    }

    // Ignore failures that are triggered after we have found the end URL
    if ( _complete == YES )
    {
        //We expect to get an error here, as we intentionally fail to navigate to the final redirect URL.
        AD_LOG_VERBOSE(@"Expected error", [error localizedDescription]);
        return;
    }
    
    [self dispatchError:error];
}
#endif

#if !(TARGET_OS_IPHONE)

-(void) handleOSXError: (NSError*) error
            toFrame: (WebFrame*) frame
{
    // TODO: This method can be called after wake from sleep when the network connection is not yet available
    if ( !_complete )
    {//In OS X we mark completion on error:
        _complete = YES;
        
        [frame stopLoading];
        
        [self dispatchError:error];
    }
    else
    {
        //Still log the error, but it is not critical:
        AD_LOG_WARN(@"WebView Error", error.description);
    }
}
#endif //!(TARGET_OS_IPHONE)

#if !(TARGET_OS_IPHONE)
- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
#pragma unused(sender)
    [self handleOSXError:error toFrame:frame];
}
#endif //TARGET_OS_IPHONE

#if !(TARGET_OS_IPHONE)
- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
#pragma unused(sender)
    [self handleOSXError:error toFrame:frame];
}
#endif //TARGET_OS_IPHONE

#if !(TARGET_OS_IPHONE)
- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource
{
#pragma unused(sender)
#pragma unused(identifier)
#pragma unused(dataSource)
    
    DebugLog( @"URL: %@", request.URL.absoluteString );
    
    if ( redirectResponse )
    {
        [self.class.cookieJar setCookiesFromResponse:redirectResponse];
    }
    
    // Rebuild the request to use our cookie jar
    NSMutableURLRequest *newRequest = [NSMutableURLRequest requestWithURL:request.URL cachePolicy:request.cachePolicy timeoutInterval:request.timeoutInterval];
    
    newRequest.HTTPMethod = request.HTTPMethod;
    
    if ( request.HTTPBodyStream )
        newRequest.HTTPBodyStream = request.HTTPBodyStream;
    else
        newRequest.HTTPBody = request.HTTPBody;
    
    newRequest.HTTPShouldHandleCookies = NO; // Set this to NO to tell the request to not look for and send cookies
    newRequest.HTTPShouldUsePipelining = request.HTTPShouldUsePipelining;
    
    // Get the cookies for the request
    NSArray             *cookies       = [self.class.cookieJar getCookiesForRequest:newRequest];
    NSDictionary        *cookieHeaders = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
    NSMutableDictionary *headers       = [NSMutableDictionary dictionaryWithDictionary:request.allHTTPHeaderFields];
    
    // Place all the cookie headers onto the request
    [cookieHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
        if ( stop ) *stop = NO;
        [headers setObject:value forKey:key];
    }];
    
    newRequest.allHTTPHeaderFields = headers;
    
    return newRequest;
}
#endif //!(TARGET_OS_IPHONE)


#error Add the rest of the handlers
@end
