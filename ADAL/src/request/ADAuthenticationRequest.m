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


#import "ADAL_Internal.h"
#import "ADAuthenticationRequest.h"
#import "ADInstanceDiscovery.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"
#import "NSURL+ADExtensions.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"

#if TARGET_OS_IPHONE
#import "ADBrokerKeyHelper.h"
#endif

#import "ADAuthenticationRequest+WebRequest.h"
#import "ADUserIdentifier.h"

#include <libkern/OSAtomic.h>

// Used to make sure one interactive request is going on at a time,
// either launching webview or broker
static dispatch_semaphore_t sInteractionInProgress = nil;

@implementation ADAuthenticationRequest

@synthesize logComponent = _logComponent;

#define RETURN_IF_NIL(_X) { if (!_X) { AD_LOG_ERROR(@#_X " must not be nil!", AD_FAILED, nil, nil); SAFE_ARC_RELEASE(self); return nil; } }
#define ERROR_RETURN_IF_NIL(_X) { \
    if (!_X) { \
        if (error) { \
            *error = [ADAuthenticationError errorFromArgument:_X argumentName:@#_X correlationId:context.correlationId]; \
        } \
        return nil; \
    } \
}

+ (void)initialize
{
    sInteractionInProgress = dispatch_semaphore_create(1);
}

+ (ADAuthenticationRequest *)requestWithAuthority:(NSString *)authority
{
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority validateAuthority:NO error:nil];
    
    return [self requestWithContext:context];
}

+ (ADAuthenticationRequest *)requestWithContext:(ADAuthenticationContext *)context
{
    ADAuthenticationRequest* request = [[ADAuthenticationRequest alloc] init];
    if (!request)
    {
        return nil;
    }
    SAFE_ARC_AUTORELEASE(request);
    
    request->_context = context;
    
    return request;
}

+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                 requestParams:(ADRequestParameters*)requestParams
                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL([requestParams clientId]);
    
    ADAuthenticationRequest *request = [[ADAuthenticationRequest alloc] initWithContext:context requestParams:requestParams];
    SAFE_ARC_AUTORELEASE(request);
    return request;
}

- (id)initWithContext:(ADAuthenticationContext*)context
        requestParams:(ADRequestParameters*)requestParams
{
    RETURN_IF_NIL(context);
    RETURN_IF_NIL([requestParams clientId]);
    
    if (!(self = [super init]))
        return nil;
    
    SAFE_ARC_RETAIN(context);
    _context = context;
    SAFE_ARC_RETAIN(requestParams);
    _requestParams = requestParams;
    
    _promptBehavior = AD_PROMPT_AUTO;
    
    // This line is here to suppress a analyzer warning, has no effect
    _allowSilent = NO;
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_context);
    SAFE_ARC_RELEASE(_requestParams);
    SAFE_ARC_RELEASE(_scope);
    SAFE_ARC_RELEASE(_queryParams);
    SAFE_ARC_RELEASE(_refreshTokenCredential);
    SAFE_ARC_RELEASE(_underlyingError);
    
    SAFE_ARC_SUPER_DEALLOC();
}

#define CHECK_REQUEST_STARTED { \
    if (_requestStarted) { \
        NSString* _details = [NSString stringWithFormat:@"call to %s after the request started. call has no effect.", __PRETTY_FUNCTION__]; \
        AD_LOG_WARN(_details, nil, nil); \
        return; \
    } \
}

- (void)setScope:(NSString *)scope
{
    CHECK_REQUEST_STARTED;
    if (_scope == scope)
    {
        return;
    }
    SAFE_ARC_RELEASE(_scope);
    _scope = [scope copy];
}

- (void)setExtraQueryParameters:(NSString *)queryParams
{
    CHECK_REQUEST_STARTED;
    if (_queryParams == queryParams)
    {
        return;
    }
    SAFE_ARC_RELEASE(_queryParams);
    _queryParams = [queryParams copy];
}

- (void)setUserIdentifier:(ADUserIdentifier *)identifier
{
    CHECK_REQUEST_STARTED;
    if ([_requestParams identifier] == identifier)
    {
        return;
    }
    [_requestParams setIdentifier:identifier];
}

- (void)setUserId:(NSString *)userId
{
    CHECK_REQUEST_STARTED;
    [self setUserIdentifier:[ADUserIdentifier identifierWithId:userId]];
}

- (void)setPromptBehavior:(ADPromptBehavior)promptBehavior
{
    CHECK_REQUEST_STARTED;
    _promptBehavior = promptBehavior;
}

- (void)setSilent:(BOOL)silent
{
    CHECK_REQUEST_STARTED;
    _silent = silent;
}

- (void)setCorrelationId:(NSUUID*)correlationId
{
    CHECK_REQUEST_STARTED;
    if ([_requestParams correlationId] == correlationId)
    {
        return;
    }
    [_requestParams setCorrelationId:correlationId];
}

#if AD_BROKER

- (NSString*)redirectUri
{
    return _redirectUri;
}

- (void)setRedirectUri:(NSString *)redirectUri
{
    // We knowingly do this mid-request when we have to change auth types
    // Thus no CHECK_REQUEST_STARTED
    if (_redirectUri == redirectUri)
    {
        return;
    }
    SAFE_ARC_RELEASE(_redirectUri);
    _redirectUri = [redirectUri copy];
}

- (void)setAllowSilentRequests:(BOOL)allowSilent
{
    CHECK_REQUEST_STARTED;
    _allowSilent = allowSilent;
}

- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential
{
    CHECK_REQUEST_STARTED;
    if (_refreshTokenCredential == refreshTokenCredential)
    {
        return;
    }
    SAFE_ARC_RELEASE(_refreshTokenCredential);
    _refreshTokenCredential = [refreshTokenCredential copy];
}
#endif

- (void)setSamlAssertion:(NSString *)samlAssertion
{
    CHECK_REQUEST_STARTED;
    if (_samlAssertion == samlAssertion)
    {
        return;
    }
    
    SAFE_ARC_RELEASE(_samlAssertion);
    _samlAssertion = [samlAssertion copy];
}

- (void)setAssertionType:(ADAssertionType)assertionType
{
    CHECK_REQUEST_STARTED;
    
    _assertionType = assertionType;
}

- (void)ensureRequest
{
    if (_requestStarted)
    {
        return;
    }
    
    [self correlationId];
    
    _requestStarted = YES;
}

- (NSUUID*)correlationId
{
    if ([_requestParams correlationId] == nil)
    {
        //if correlationId is set in context, use it
        //if not, generate one
        if ([_context correlationId])
        {
            [_requestParams setCorrelationId:[_context correlationId]];
        } else {
            [_requestParams setCorrelationId:[NSUUID UUID]];
        }
    }
    
    return [_requestParams correlationId];
}

- (NSString*)telemetryRequestId
{
    if ([_requestParams telemetryRequestId] == nil)
    {
        [_requestParams setTelemetryRequestId:[[ADTelemetry sharedInstance] registerNewRequest]];
    }
    
    return [_requestParams telemetryRequestId];
}

- (BOOL)takeUserInterationLock
{
    return !dispatch_semaphore_wait(sInteractionInProgress, DISPATCH_TIME_NOW);
}

- (BOOL)releaseUserInterationLock
{
    dispatch_semaphore_signal(sInteractionInProgress);
    return YES;
}

@end
