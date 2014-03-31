//
//  ADAuthenticationWebViewControllerOSXWindowController.m
//  ADAL-OSX
//
//  Created by Boris Vidolov on 3/31/14.
//  Copyright (c) 2014 Boris Vidolov. All rights reserved.
//

#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationDelegate.h"

@interface ADAuthenticationWebViewController ()
{
    __weak WebViewType *_webView;
    
    NSURL    *_startURL;
    NSString *_endURL;
    BOOL      _complete;
}

@end

@implementation ADAuthenticationWebViewController

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
        [_webView setFrameLoadDelegate:self];
        [_webView setResourceLoadDelegate:self];
        [_webView setPolicyDelegate:self];
        _delegate = nil;
    }
    
    return self;
}

- (void)dealloc
{
    // The ADAuthenticationWebViewController can be released before the
    // UIWebView that it is managing is released in the hosted case and
    // so it is important that to stop listening for events from the
    // UIWebView when we are released.
    _webView.frameLoadDelegate    = nil;
    _webView.resourceLoadDelegate = nil;
    _webView.policyDelegate       = nil;
    _webView          = nil;
}

- (void)start
{
    NSURLRequest *request = [NSURLRequest requestWithURL:_startURL];
    
    // Start the authentication process
    [_webView.mainFrame loadRequest:request];
}

- (void)stop
{
    //In future this method may be expanded to clear some state like cookies
}


-(void) handleError: (NSError*) error
            toFrame: (WebFrame*) frame
{
    // TODO: This method can be called after wake from sleep when the network connection is not yet available
    if ( !_complete )
    {//mark completion on error:
        _complete = YES;
        
        [frame stopLoading];
        
        AD_LOG_WARN(@"authorization error", [error localizedDescription]);
        
        // Tell our delegate that we are done after an error.
        if (_delegate)
        {
            [self.delegate webAuthenticationDidFailWithError:error];
        }
        else
        {
            AD_LOG_ERROR(@"Delegate object is lost", AD_ERROR_APPLICATION, @"The delegate object was lost, potentially due to another concurrent request.");
        }
    }
    else
    {
        //Still log the error, but it is not critical:
        AD_LOG_WARN(@"WebView Error", error.description);
    }
}

- (void)webView:(WebView *)sender didFailProvisionalLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
#pragma unused(sender)
    [self handleError:error toFrame:frame];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
#pragma unused(sender)
    [self handleError:error toFrame:frame];
}

- (void)webView:(WebView *)webView decidePolicyForNavigationAction:(NSDictionary *)actionInformation
        request:(NSURLRequest *)request
          frame:(WebFrame *)frame
decisionListener:(id<WebPolicyDecisionListener>)listener;
{
#pragma unused(webView)
#pragma unused(actionInformation)
    
    NSString *currentURL = [[request.URL absoluteString] lowercaseString];
    
    if ( [currentURL hasPrefix:_endURL] )
    {
        _complete = YES;
        
        [listener ignore];
        [frame stopLoading];
        
        // NOTE: Synchronous invocation
        NSAssert( nil != _delegate, @"Delegate has been lost" );
        [self.delegate webAuthenticationDidCompleteWithURL:request.URL];
    }
    else
    {
        [listener use];
    }
}


//TODO: Determine if this is even needed. The current logic is in place due to the cookie manipulation
//- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource
//{
//#pragma unused(sender)
//#pragma unused(identifier)
//#pragma unused(dataSource)
//
//    DebugLog( @"URL: %@", request.URL.absoluteString );
//
//    if ( redirectResponse )
//    {
//        [self.class.cookieJar setCookiesFromResponse:redirectResponse];
//    }
//
//    // Rebuild the request to use our cookie jar
//    NSMutableURLRequest *newRequest = [NSMutableURLRequest requestWithURL:request.URL cachePolicy:request.cachePolicy timeoutInterval:request.timeoutInterval];
//
//    newRequest.HTTPMethod = request.HTTPMethod;
//
//    if ( request.HTTPBodyStream )
//        newRequest.HTTPBodyStream = request.HTTPBodyStream;
//    else
//        newRequest.HTTPBody = request.HTTPBody;
//
//    newRequest.HTTPShouldHandleCookies = NO; // Set this to NO to tell the request to not look for and send cookies
//    newRequest.HTTPShouldUsePipelining = request.HTTPShouldUsePipelining;
//
//    // Get the cookies for the request
//    NSArray             *cookies       = [self.class.cookieJar getCookiesForRequest:newRequest];
//    NSDictionary        *cookieHeaders = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
//    NSMutableDictionary *headers       = [NSMutableDictionary dictionaryWithDictionary:request.allHTTPHeaderFields];
//
//    // Place all the cookie headers onto the request
//    [cookieHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
//        if ( stop ) *stop = NO;
//        [headers setObject:value forKey:key];
//    }];
//
//    newRequest.allHTTPHeaderFields = headers;
//
//    return newRequest;
//}

//TODO: Consider if this is needed. Again only used for cookies:
//- (void)webView:(WebView *)sender resource:(id)identifier didReceiveResponse:(NSURLResponse *)response fromDataSource:(WebDataSource *)dataSource
//{
//#pragma unused(sender)
//#pragma unused(identifier)
//#pragma unused(dataSource)
//
//    [self.class.cookieJar setCookiesFromResponse:response];
//}


@end
