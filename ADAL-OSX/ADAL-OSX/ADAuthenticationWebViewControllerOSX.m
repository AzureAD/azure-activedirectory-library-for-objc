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

#import "ADAuthenticationWebViewController.h"
#import "ADAuthenticationDelegate.h"
#import "ADCredentialCollectionController.h"
#import "ADNTLMHandler.h"
//#import "ADPkeyAuthHelper.h"
//#import "WorkPlaceJoinConstants.h"
//#import "WorkplaceJoin.h"

@interface ADAuthenticationWebViewController ()

@end

@implementation ADAuthenticationWebViewController

@synthesize delegate = _delegate;

- (id)initWithWebView:(WebViewType *)webView startAtURL:(NSURL *)startURL endAtURL:(NSURL *)endURL
{
    if ( nil == startURL || nil == endURL )
        return nil;
    
    if ( nil == webView )
        return nil;
    
    if ( ( self = [super init] ) != nil )
    {
        _parentDelegate = [webView policyDelegate];
        _startURL  = [startURL copy];
        _endURL    = SAFE_ARC_RETAIN([[endURL absoluteString] lowercaseString]);
        
        _complete  = NO;
        
        _webView   = webView;
        [_webView setFrameLoadDelegate:self];
        [_webView setResourceLoadDelegate:self];
        [_webView setPolicyDelegate:self];
        _delegate = nil;
   }
    
    return self;
}

- (void)dealloc
{
    AD_LOG_VERBOSE(@"ADAuthenticationWebViewController", @"dealloc");
    
    // The ADAuthenticationWebViewController can be released before the
    // UIWebView that it is managing is released in the hosted case and
    // so it is important that to stop listening for events from the
    // UIWebView when we are released.
    _webView.frameLoadDelegate    = nil;
    _webView.resourceLoadDelegate = nil;
    _webView.policyDelegate       = nil;
    _webView                      = nil;
    
    SAFE_ARC_RELEASE(_startURL);
    SAFE_ARC_RELEASE(_endURL);
    
    SAFE_ARC_SUPER_DEALLOC();
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
    if ([_parentDelegate respondsToSelector:@selector(webView:didFailProvisionalLoadWithError:forFrame:)])
        [_parentDelegate webView:sender didFailProvisionalLoadWithError:error forFrame:frame];
    [self handleError:error toFrame:frame];
}

- (void)webView:(WebView *)sender didFailLoadWithError:(NSError *)error forFrame:(WebFrame *)frame
{
#pragma unused(sender)
    if ([_parentDelegate respondsToSelector:@selector(webView:didFailLoadWithError:forFrame:)])
        [_parentDelegate webView:sender didFailLoadWithError:error forFrame:frame];

    if (NSURLErrorCancelled == error.code)
    {
        //This is a common error that webview generates and could be ignored.
        //See this thread for details: https://discussions.apple.com/thread/1727260
        return;
    }
    
    [self handleError:error toFrame:frame];
}


//
//- (void) handlePKeyAuthChallenge:(NSString *)challengeUrl
//{
//    NSArray * parts = [challengeUrl componentsSeparatedByString:@"?"];
//    NSString *qp = [parts objectAtIndex:1];
//    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
//    NSString* value = [queryParamsMap valueForKey:@"SubmitUrl"];
//    
//    NSArray * authorityParts = [value componentsSeparatedByString:@"?"];
//    NSString *authority = [authorityParts objectAtIndex:0];
//    
//    NSMutableURLRequest* responseUrl = [[NSMutableURLRequest alloc] initWithURL: [NSURL URLWithString: value]];
//    
//    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:authority challengeData:queryParamsMap];
//    
//    [responseUrl setValue:pKeyAuthHeaderVersion forHTTPHeaderField: pKeyAuthHeader];
//    [responseUrl setValue:authHeader forHTTPHeaderField:@"Authorization"];
//    [_webView.mainFrame loadRequest:responseUrl];
//}


- (void)webView:(WebView *)webView decidePolicyForNavigationAction:(NSDictionary *)actionInformation
        request:(NSURLRequest *)request
          frame:(WebFrame *)frame
decisionListener:(id<WebPolicyDecisionListener>)listener
{
#pragma unused(webView)
#pragma unused(actionInformation)
    if ([_parentDelegate respondsToSelector:@selector(webView: decidePolicyForNavigationAction:request:frame:decisionListener:)]){
        [_parentDelegate webView:webView decidePolicyForNavigationAction:actionInformation request:request frame:frame decisionListener:listener];
    }
    
    //NSString *requestURL = [request.URL absoluteString];
    NSString *currentURL = [[request.URL absoluteString] lowercaseString];
    
    // check for pkeyauth challenge.
//    if ([requestURL hasPrefix: pKeyAuthUrn] )
//    {
//        [self handlePKeyAuthChallenge: requestURL];
//        return;
//    }
    
 //   if ( [requestURL hasPrefix:_endURL] )
    
    
    if([ADNTLMHandler isChallengeCancelled]){
        _complete = YES;
        [listener ignore];
        [frame stopLoading];
        NSAssert( nil != _delegate, @"Delegate has been lost" );
        [self.delegate webAuthenticationDidCancel];
        return;
    }
    
    
    if ( [currentURL hasPrefix:_endURL])
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
        
//        if([[WorkPlaceJoin WorkPlaceJoinManager] isWorkPlaceJoined] && ![request.allHTTPHeaderFields valueForKey:pKeyAuthHeader]){
//            // Create a mutable copy of the immutable request and add more headers
//            NSMutableURLRequest *mutableRequest = [request mutableCopy];
//            [mutableRequest addValue:pKeyAuthHeaderVersion forHTTPHeaderField:pKeyAuthHeader];
//            
//            // Now set our request variable with an (immutable) copy of the altered request
//            request = [mutableRequest copy];
//            [_webView.mainFrame loadRequest:request];
//            return;
//        }
//        
//        if ([[[request.URL scheme] lowercaseString] isEqualToString:@"browser"]) {
//            requestURL = [requestURL stringByReplacingOccurrencesOfString:@"browser://" withString:@"https://"];
//            [[NSWorkspace sharedWorkspace] openURL:[[NSURL alloc] initWithString:requestURL]];
//            return;
//        }
        
        [listener use];
    }
}

- (void)forwardInvocation:(NSInvocation *)anInvocation
{
    if ([_parentDelegate respondsToSelector:[anInvocation selector]])
        [anInvocation invokeWithTarget:_parentDelegate];
    else
        [super forwardInvocation:anInvocation];
}

- (BOOL)respondsToSelector:(SEL)aSelector
{
    return [super respondsToSelector:aSelector] || [_parentDelegate respondsToSelector:aSelector];
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector
{
    NSMethodSignature *signature = [super methodSignatureForSelector:selector];
    if (!signature) {
        signature = [_parentDelegate methodSignatureForSelector:selector];
    }
    return signature;
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
