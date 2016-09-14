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

#if TARGET_OS_IPHONE
#import "UIApplication+ADExtensions.h"
#import "ADAppExtensionUtil.h"
#endif
#import "NSDictionary+ADExtensions.h"

#import "ADWebAuthController+Internal.h"

#import "ADAuthenticationViewController.h"
#import "ADAuthenticationSettings.h"
#import "ADCustomHeaderHandler.h"
#import "ADHelpers.h"
#import "ADNTLMHandler.h"
#import "ADOAuth2Constants.h"
#import "ADPkeyAuthHelper.h"
#import "ADURLProtocol.h"
#import "ADWebAuthDelegate.h"
#import "ADWorkPlaceJoinConstants.h"

/*! Fired at the start of a resource load in the webview. */
NSString* ADWebAuthDidStartLoadNotification = @"ADWebAuthDidStartLoadNotification";

/*! Fired when a resource finishes loading in the webview. */
NSString* ADWebAuthDidFinishLoadNotification = @"ADWebAuthDidFinishLoadNotification";

/*! Fired when web authentication fails due to reasons originating from the network. */
NSString* ADWebAuthDidFailNotification = @"ADWebAuthDidFailNotification";

/*! Fired when authentication finishes */
NSString* ADWebAuthDidCompleteNotification = @"ADWebAuthDidCompleteNotification";

NSString* ADWebAuthDidReceieveResponseFromBroker = @"ADWebAuthDidReceiveResponseFromBroker";

NSString* ADWebAuthWillSwitchToBrokerApp = @"ADWebAuthWillSwitchToBrokerApp";

// Private interface declaration
@interface ADWebAuthController () <ADWebAuthDelegate>
@end

// Implementation
@implementation ADWebAuthController

#pragma mark Shared Instance Methods

+ (id)alloc
{
    NSAssert( false, @"Cannot create instances of %@", NSStringFromClass( self ) );
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:[NSString stringWithFormat:@"Cannot create instances of %@", NSStringFromClass( self )] userInfo:nil];
    
    return nil;
}

+ (id)allocPrivate
{
    // [super alloc] calls to NSObject, and that calls [class allocWithZone:]
    return [super alloc];
}

+ (id)new
{
    return [self alloc];
}

- (id)copy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

- (id)mutableCopy
{
    NSAssert( false, @"Cannot copy instances of %@", NSStringFromClass( [self class] ) );
    
    return [[self class] sharedInstance];
}

#pragma mark - Initialization

- (id)init
{
    self = [super init];
    
    if ( self )
    {
        _completionLock = [[NSLock alloc] init];
    }
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_completionLock);
    _completionLock = nil;
    SAFE_ARC_RELEASE(_endURL);
    _endURL = nil;
    SAFE_ARC_RELEASE(_spinnerTimer);
    _spinnerTimer = nil;
    SAFE_ARC_RELEASE(_loadingTimer);
    _loadingTimer = nil;
    SAFE_ARC_RELEASE(_completionBlock);
    _completionBlock = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

+ (void)cancelCurrentWebAuthSession
{
    [[ADWebAuthController sharedInstance] webAuthDidCancel];
}

#pragma mark - Private Methods

- (void)dispatchCompletionBlock:(ADAuthenticationError *)error URL:(NSURL *)url
{
    // NOTE: It is possible that competition between a successful completion
    //       and the user cancelling the authentication dialog can
    //       occur causing this method to be called twice. The competition
    //       cannot be blocked at its root, and so this method must
    //       be resilient to this condition and should not generate
    //       two callbacks.
    [_completionLock lock];
    
    [ADURLProtocol unregisterProtocol];
    
    if ( _completionBlock )
    {
        void (^completionBlock)( ADAuthenticationError *, NSURL *) = _completionBlock;
        _completionBlock = nil;
        
        dispatch_async( dispatch_get_main_queue(), ^{
            completionBlock( error, url );
            SAFE_ARC_RELEASE(completionBlock);
        });
    }
    
    [_completionLock unlock];
}

- (void)handlePKeyAuthChallenge:(NSString *)challengeUrl
{
    
    AD_LOG_VERBOSE(@"Handling PKeyAuth Challenge", nil, nil);
    
    NSArray * parts = [challengeUrl componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    NSString* value = [ADHelpers addClientVersionToURLString:[queryParamsMap valueForKey:@"SubmitUrl"]];
    
    NSArray * authorityParts = [value componentsSeparatedByString:@"?"];
    NSString *authority = [authorityParts objectAtIndex:0];
    
    ADAuthenticationError* adError = nil;
    NSString* authHeader = [ADPkeyAuthHelper createDeviceAuthResponse:authority
                                                        challengeData:queryParamsMap
                                                        correlationId:_correlationId
                                                                error:&adError];
    if (!authHeader)
    {
        [self dispatchCompletionBlock:adError URL:nil];
        return;
    }
    
    NSMutableURLRequest* responseUrl = [[NSMutableURLRequest alloc]initWithURL:[NSURL URLWithString:value]];
    [ADURLProtocol addCorrelationId:_correlationId toRequest:responseUrl];
    
    [responseUrl setValue:pKeyAuthHeaderVersion forHTTPHeaderField: pKeyAuthHeader];
    [responseUrl setValue:authHeader forHTTPHeaderField:@"Authorization"];
    [_authenticationViewController loadRequest:responseUrl];
    SAFE_ARC_RELEASE(responseUrl);
}

- (BOOL)endWebAuthenticationWithError:(ADAuthenticationError*) error
                                orURL:(NSURL*)endURL
{
    if (!_authenticationViewController)
    {
        return NO;
    }
    
    [_authenticationViewController stop:^{[self dispatchCompletionBlock:error URL:endURL];}];
    SAFE_ARC_RELEASE(_authenticationViewController);
    _authenticationViewController = nil;
    
    return YES;
}

- (void)onStartActivityIndicator:(id)sender
{
#pragma unused(sender)
    
    if (_loading)
    {
        [_authenticationViewController startSpinner];
    }
    
    SAFE_ARC_RELEASE(_spinnerTimer);
    _spinnerTimer = nil;
}

- (void)stopSpinner
{
    if (!_loading)
    {
        return;
    }
    
    _loading = NO;
    if (_spinnerTimer)
    {
        [_spinnerTimer invalidate];
        SAFE_ARC_RELEASE(_spinnerTimer);
        _spinnerTimer = nil;
    }
    
    [_authenticationViewController stopSpinner];
}


- (void)failWithTimeout
{
    SAFE_ARC_RELEASE(_loadingTimer);
    _loadingTimer = nil;
    [_authenticationViewController stop:^{
        NSError* error = [NSError errorWithDomain:NSURLErrorDomain
                                             code:NSURLErrorTimedOut
                                         userInfo:nil];
        ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error errorDetails:@"WebView timed out" correlationId:_correlationId];
        [self dispatchCompletionBlock:adError URL:nil];
    }];
}

#pragma mark - ADWebAuthDelegate

- (void)webAuthDidStartLoad:(NSURL*)url
{
    if (!_loading)
    {
        _loading = YES;
        if (_spinnerTimer)
        {
            [_spinnerTimer invalidate];
            SAFE_ARC_RELEASE(_spinnerTimer);
        }
        _spinnerTimer = [NSTimer scheduledTimerWithTimeInterval:2.0
                                                         target:self
                                                       selector:@selector(onStartActivityIndicator:)
                                                       userInfo:nil
                                                        repeats:NO];
        [_spinnerTimer setTolerance:0.3];
        SAFE_ARC_RETAIN(_spinnerTimer);
    }
    
    if (_loadingTimer)
    {
        [_loadingTimer invalidate];
        SAFE_ARC_RELEASE(_loadingTimer);
        _loadingTimer = nil;
    }
    
    _loadingTimer = [NSTimer scheduledTimerWithTimeInterval:_timeout
                                                     target:self
                                                   selector:@selector(failWithTimeout)
                                                   userInfo:nil
                                                    repeats:NO];
    // Tolerance is how much "float" the system is allowed to use to try to group the timer with other events
    // on the system.
    [_loadingTimer setTolerance:4.0];
    SAFE_ARC_RETAIN(_loadingTimer);
    
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidStartLoadNotification object:self userInfo:url ? @{ @"url" : url } : nil];
}

- (void)webAuthDidFinishLoad:(NSURL*)url
{
    AD_LOG_VERBOSE_F(@"-webAuthDidFinishLoad:", _correlationId, @"host: %@", url.host);
    [self stopSpinner];
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidFinishLoadNotification object:self userInfo:url ? @{ @"url" : url } : nil];
}

- (BOOL)webAuthShouldStartLoadRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(@"-webAuthShouldStartLoadRequest:", _correlationId, @"host: %@", request.URL.host);
    if([ADNTLMHandler isChallengeCancelled])
    {
        _complete = YES;
        dispatch_async( dispatch_get_main_queue(), ^{[self webAuthDidCancel];});
        return NO;
    }
    
    NSString *requestURL = [request.URL absoluteString];

    if ([[requestURL lowercaseString] isEqualToString:@"about:blank"])
    {
        return NO;
    }
    
    if ([[[request.URL scheme] lowercaseString] isEqualToString:@"browser"])
    {
        _complete = YES;
#if TARGET_OS_IPHONE
        if (![ADAppExtensionUtil isExecutingInAppExtension])
        {
            dispatch_async( dispatch_get_main_queue(), ^{
                [self webAuthDidCancel];
            });
            
            requestURL = [requestURL stringByReplacingOccurrencesOfString:@"browser://" withString:@"https://"];
            
            dispatch_async( dispatch_get_main_queue(), ^{
                [ADAppExtensionUtil sharedApplicationOpenURL:[[NSURL alloc] initWithString:requestURL]];
            });
        }
        else
        {
            AD_LOG_ERROR(@"unable to redirect to browser from extension", AD_ERROR_SERVER_UNSUPPORTED_REQUEST, _correlationId, nil);
        }
#else // !TARGET_OS_IPHONE
        AD_LOG_ERROR(@"server is redirecting us to browser, this behavior is not defined on Mac OS X yet", AD_ERROR_SERVER_UNSUPPORTED_REQUEST, _correlationId, nil);
#endif // TARGET_OS_IPHONE
        return NO;
    }
    
    // Stop at the end URL.
    if ([[requestURL lowercaseString] hasPrefix:[_endURL lowercaseString]] ||
        [[[request.URL scheme] lowercaseString] isEqualToString:@"msauth"])
    {
        // iOS generates a 102, Frame load interrupted error from stopLoading, so we set a flag
        // here to note that it was this code that halted the frame load in order that we can ignore
        // the error when we are notified later.
        _complete = YES;
        
#if AD_BROKER
        // If we're in the broker and we get a url with msauth that means we got an auth code back from the
        // client cert auth flow
        if ([[[request.URL scheme] lowercaseString] isEqualToString:@"msauth"])
        {
            dispatch_async( dispatch_get_main_queue(), ^{ [_delegate webAuthDidCompleteWithURL:request.URL]; } );
            return NO;
        }
#endif

        NSURL* url = request.URL;
        [self webAuthDidCompleteWithURL:url];
        
        // Tell the web view that this URL should not be loaded.
        return NO;
    }
    
    // check for pkeyauth challenge.
    if ([requestURL hasPrefix:pKeyAuthUrn])
    {
        // We still continue onwards from a pkeyauth challenge after it's handled, so the web auth flow
        // is not complete yet.
        [self handlePKeyAuthChallenge:requestURL];
        return NO;
    }
    
    // redirecting to non-https url is not allowed
    if (![[[request.URL scheme] lowercaseString] isEqualToString:@"https"])
    {
        AD_LOG_ERROR(@"Server is redirecting to a non-https url", AD_ERROR_SERVER_NON_HTTPS_REDIRECT, nil, nil);
        _complete = YES;
        ADAuthenticationError* error = [ADAuthenticationError errorFromNonHttpsRedirect:_correlationId];
        dispatch_async( dispatch_get_main_queue(), ^{[self endWebAuthenticationWithError:error orURL:nil];} );
        
        return NO;
    }
    
    if ([request isKindOfClass:[NSMutableURLRequest class]])
    {
        [ADURLProtocol addCorrelationId:_correlationId toRequest:(NSMutableURLRequest*)request];
    }
    
    return YES;
}

// The user cancelled authentication
- (void)webAuthDidCancel
{
    AD_LOG_INFO(@"-webAuthDidCancel", _correlationId, nil);
    
    // Dispatch the completion block
    
    ADAuthenticationError* error = [ADAuthenticationError errorFromCancellation:_correlationId];
    [self endWebAuthenticationWithError:error orURL:nil];
}

// Authentication completed at the end URL
- (void)webAuthDidCompleteWithURL:(NSURL *)endURL
{
    AD_LOG_INFO_F(@"-webAuthDidCompleteWithURL:", _correlationId, @"%@", endURL);

    [self endWebAuthenticationWithError:nil orURL:endURL];
    [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidCompleteNotification object:self userInfo:nil];
}

// Authentication failed somewhere
- (void)webAuthDidFailWithError:(NSError *)error
{
    // Ignore WebKitError 102 for OAuth 2.0 flow.
    if ([error.domain isEqualToString:@"WebKitErrorDomain"] && error.code == 102)
    {
        return;
    }
    
    // Prior to iOS 10 the WebView trapped out this error code and didn't pass it along to us
    // now we have to trap it out ourselves.
    if ([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSUserCancelledError)
    {
        return;
    }
    
    // If we failed on an invalid URL check to see if it matches our end URL
    if ([error.domain isEqualToString:@"NSURLErrorDomain"] && (error.code == -1002 || error.code == -1003))
    {
        NSURL* url = [error.userInfo objectForKey:NSURLErrorFailingURLErrorKey];
        NSString* urlString = [url absoluteString];
        if ([[urlString lowercaseString] hasPrefix:_endURL.lowercaseString])
        {
            _complete = YES;
            [self webAuthDidCompleteWithURL:url];
            return;
        }
        
        // check for pkeyauth challenge.
        if ([urlString hasPrefix:pKeyAuthUrn])
        {
            // We still continue onwards from a pkeyauth challenge after it's handled, so the web auth flow
            // is not complete yet.
            [self handlePKeyAuthChallenge:urlString];
            return;
        }
    }

    if (error)
    {
        AD_LOG_ERROR_F(@"-webAuthDidFailWithError:", error.code, _correlationId, @"error: %@", error);

        [[NSNotificationCenter defaultCenter] postNotificationName:ADWebAuthDidFailNotification
                                                            object:self
                                                          userInfo:@{ @"error" : error}];
    }
    
    [self stopSpinner];
    if (_loadingTimer)
    {
        [_loadingTimer invalidate];
        SAFE_ARC_RELEASE(_loadingTimer);
        _loadingTimer = nil;
    }
    
    if (NSURLErrorCancelled == error.code)
    {
        //This is a common error that webview generates and could be ignored.
        //See this thread for details: https://discussions.apple.com/thread/1727260
        return;
    }
    
    if([error.domain isEqual:@"WebKitErrorDomain"])
    {
        return;
    }
    
    // Ignore failures that are triggered after we have found the end URL
    if (_complete == YES)
    {
        //We expect to get an error here, as we intentionally fail to navigate to the final redirect URL.
        AD_LOG_VERBOSE(@"Expected error", _correlationId, [error localizedDescription]);
        return;
    }
    
    // Dispatch the completion block
    __block ADAuthenticationError* adError = [ADAuthenticationError errorFromNSError:error errorDetails:error.localizedDescription correlationId:_correlationId];
    
    dispatch_async(dispatch_get_main_queue(), ^{ [self endWebAuthenticationWithError:adError orURL:nil]; });
}

#if TARGET_OS_IPHONE
static ADAuthenticationResult* s_result = nil;

+ (ADAuthenticationResult*)responseFromInterruptedBrokerSession
{
    ADAuthenticationResult* result = s_result;
    s_result = nil;
    return result;
}
#endif // TARGET_OS_IPHONE

@end

#pragma mark - Private Methods

@implementation ADWebAuthController (Internal)

+ (ADWebAuthController *)sharedInstance
{
    static ADWebAuthController *broker     = nil;
    static dispatch_once_t          predicate;
    
    dispatch_once( &predicate, ^{
        broker = [[self allocPrivate] init];
    });
    
    return broker;
}

- (BOOL)cancelCurrentWebAuthSessionWithError:(ADAuthenticationError*)error
{
    return [self endWebAuthenticationWithError:error orURL:nil];
}

-(NSURL*) addToURL: (NSURL*) url
     correlationId: (NSUUID*) correlationId
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"%@&%@=%@",
                                 [url absoluteString], OAUTH2_CORRELATION_ID_REQUEST_VALUE, [correlationId UUIDString]]];
}

- (void)start:(NSURL *)startURL
          end:(NSURL *)endURL
  refreshCred:(NSString *)refreshCred
#if TARGET_OS_IPHONE
       parent:(UIViewController *)parent
   fullScreen:(BOOL)fullScreen
#endif
      webView:(WebViewType *)webView
correlationId:(NSUUID *)correlationId
   completion:(ADBrokerCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(startURL);
    THROW_ON_NIL_ARGUMENT(endURL);
    THROW_ON_NIL_ARGUMENT(correlationId);
    THROW_ON_NIL_ARGUMENT(completionBlock);
    
    // If we're not on the main thread when trying to kick up the UI then
    // dispatch over to the main thread.
    if (![NSThread isMainThread])
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self start:startURL
                    end:endURL
            refreshCred:refreshCred
#if TARGET_OS_IPHONE
                 parent:parent
             fullScreen:fullScreen
#endif
                webView:webView
          correlationId:correlationId
             completion:completionBlock];
        });
        return;
    }
    
    
    _timeout = [[ADAuthenticationSettings sharedInstance] requestTimeOut];
    
    startURL = [self addToURL:startURL correlationId:correlationId];//Append the correlation id
    SAFE_ARC_RELEASE(_endURL);
    _endURL = [endURL absoluteString];
    SAFE_ARC_RETAIN(_endURL);
    _complete = NO;
    
    SAFE_ARC_RELEASE(_correlationId);
    _correlationId = correlationId;
    SAFE_ARC_RETAIN(_correlationId);
    
    // Save the completion block
    SAFE_ARC_RELEASE(_completionBlock);
    _completionBlock = [completionBlock copy];
    ADAuthenticationError* error = nil;
    
    [ADURLProtocol registerProtocol:[endURL absoluteString]];
    
    if(![NSString adIsStringNilOrBlank:refreshCred])
    {
        [ADCustomHeaderHandler addCustomHeaderValue:refreshCred
                                       forHeaderKey:@"x-ms-RefreshTokenCredential"
                                       forSingleUse:YES];
    }
    
    SAFE_ARC_RELEASE(_authenticationViewController);
    _authenticationViewController = [[ADAuthenticationViewController alloc] init];
    [_authenticationViewController setDelegate:self];
    [_authenticationViewController setWebView:webView];
#if TARGET_OS_IPHONE
    [_authenticationViewController setParentController:parent];
    [_authenticationViewController setFullScreen:fullScreen];
#endif
    
    if (![_authenticationViewController loadView:&error])
    {
        _completionBlock(error, nil);
    }
    
    NSMutableURLRequest* request = [[NSMutableURLRequest alloc] initWithURL:[ADHelpers addClientVersionToURL:startURL]];
    [ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    [_authenticationViewController startRequest:request];
    SAFE_ARC_RELEASE(request);
}

#if TARGET_OS_IPHONE
+ (void)setInterruptedBrokerResult:(ADAuthenticationResult*)result
{
    s_result = result;
}
#endif // TARGET_OS_IPHONE

@end
