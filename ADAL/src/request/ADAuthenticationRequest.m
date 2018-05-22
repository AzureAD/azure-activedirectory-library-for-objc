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
#import "ADAuthorityValidation.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "NSString+ADURLExtensions.h"

#if TARGET_OS_IPHONE
#import "ADBrokerKeyHelper.h"
#endif

#import "ADAuthenticationRequest+WebRequest.h"
#import "ADUserIdentifier.h"

#include <libkern/OSAtomic.h>

static ADAuthenticationRequest* s_modalRequest = nil;
static dispatch_semaphore_t s_interactionLock = nil;

@interface ADAuthenticationRequest()

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;

@end

@implementation ADAuthenticationRequest

@synthesize logComponent = _logComponent;

#define RETURN_IF_NIL(_X) { if (!_X) { MSID_LOG_ERROR(nil, @#_X " must not be nil!"); return nil; } }
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
    s_interactionLock = dispatch_semaphore_create(1);
}

+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                 requestParams:(ADRequestParameters*)requestParams
                                    tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL([requestParams clientId]);
    
    ADAuthenticationRequest *request = [[ADAuthenticationRequest alloc] initWithContext:context
                                                                          requestParams:requestParams
                                                                             tokenCache:tokenCache];
    return request;
}

- (id)initWithContext:(ADAuthenticationContext*)context
        requestParams:(ADRequestParameters*)requestParams
           tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
{
    RETURN_IF_NIL(context);
    RETURN_IF_NIL([requestParams clientId]);
    
    if (!(self = [super init]))
        return nil;
    
    _context = context;
    _requestParams = requestParams;
    _tokenCache = tokenCache;
    
    _promptBehavior = AD_PROMPT_AUTO;
    
    // This line is here to suppress a analyzer warning, has no effect
    _allowSilent = NO;
    _skipCache = NO;
    
    return self;
}



#define CHECK_REQUEST_STARTED { \
    if (_requestStarted) { \
        MSID_LOG_WARN(nil, @"call to %s after the request started. call has no effect.", __PRETTY_FUNCTION__); \
        return; \
    } \
}

- (void)setScopesString:(NSString *)scopesString
{
    _requestParams.scopesString = scopesString;
}

- (void)setExtraQueryParameters:(NSString *)queryParams
{
    CHECK_REQUEST_STARTED;
    if (_queryParams == queryParams)
    {
        return;
    }
    _queryParams = [queryParams copy];
}

- (void)setClaims:(NSString *)claims
{
    CHECK_REQUEST_STARTED;
    if (_claims == claims)
    {
        return;
    }
    _claims = [claims copy];
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

- (void)setSkipCache:(BOOL)skipCache
{
    CHECK_REQUEST_STARTED;
    _skipCache = skipCache;
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

- (void)setCloudInstanceHostname:(NSString *)cloudInstanceHostName
{
    if (cloudInstanceHostName)
    {
        _cloudAuthority = [_context.authority adAuthorityWithCloudInstanceHostname:cloudInstanceHostName];
    }
    else
    {
        _cloudAuthority = _context.authority;
    }
    
    _requestParams.cloudAuthority = _cloudAuthority;
}

#if AD_BROKER

- (NSString*)redirectUri
{
    return _requestParams.redirectUri;
}

- (void)setRedirectUri:(NSString *)redirectUri
{
    // We knowingly do this mid-request when we have to change auth types
    // Thus no CHECK_REQUEST_STARTED
    [_requestParams setRedirectUri:redirectUri];
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
    _samlAssertion = [samlAssertion copy];
}

- (void)setAssertionType:(ADAssertionType)assertionType
{
    CHECK_REQUEST_STARTED;
    
    _assertionType = assertionType;
}

- (void)setRefreshToken:(NSString *)refreshToken
{
    CHECK_REQUEST_STARTED;
    _refreshToken = [refreshToken copy];
}

- (void)ensureRequest
{
    if (_requestStarted)
    {
        return;
    }
    
    [self correlationId];
    [self telemetryRequestId];
    
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
        [_requestParams setTelemetryRequestId:[[MSIDTelemetry sharedInstance] generateRequestId]];
    }
    
    return [_requestParams telemetryRequestId];
}

- (ADRequestParameters*)requestParams
{
    return _requestParams;
}

/*!
    Takes the UI interaction lock for the current request, will send an error
    to completionBlock if it fails.
 
    @param completionBlock  the ADAuthenticationCallback to send an error to if
                            one occurs.
 
    @return NO if we fail to take the exclusion lock
 */
- (BOOL)takeExclusionLock:(ADAuthenticationCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    if (dispatch_semaphore_wait(s_interactionLock, DISPATCH_TIME_NOW) != 0)
    {
        NSString* message = @"The user is currently prompted for credentials as result of another acquireToken request. Please retry the acquireToken call later.";
        ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_UI_MULTLIPLE_INTERACTIVE_REQUESTS
                                                                              protocolCode:nil
                                                                              errorDetails:message
                                                                             correlationId:_requestParams.correlationId];
        completionBlock([ADAuthenticationResult resultFromError:error]);
        return NO;
    }
    
    s_modalRequest = self;
    return YES;
}

/*!
    Releases the exclusion lock
 */
+ (void)releaseExclusionLock
{
    dispatch_semaphore_signal(s_interactionLock);
    s_modalRequest = nil;
}

+ (ADAuthenticationRequest*)currentModalRequest
{
    return s_modalRequest;
}

@end
