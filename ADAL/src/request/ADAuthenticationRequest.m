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

#if TARGET_OS_IPHONE
#import "ADBrokerKeyHelper.h"
#endif

#import "ADAuthenticationRequest+WebRequest.h"
#import "ADUserIdentifier.h"

#include <libkern/OSAtomic.h>

static ADAuthenticationRequest* s_modalRequest = nil;
static dispatch_semaphore_t s_interactionLock = nil;

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
    s_interactionLock = dispatch_semaphore_create(1);
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
                                   redirectUri:(NSString*)redirectUri
                                      clientId:(NSString*)clientId
                                      resource:(NSString*)resource
                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL(clientId);
    
    ADAuthenticationRequest *request = [[ADAuthenticationRequest alloc] initWithContext:context redirectUri:redirectUri clientId:clientId resource:resource];
    SAFE_ARC_AUTORELEASE(request);
    return request;
}

- (id)initWithContext:(ADAuthenticationContext*)context
          redirectUri:(NSString*)redirectUri
             clientId:(NSString*)clientId
             resource:(NSString*)resource
{
    RETURN_IF_NIL(context);
    RETURN_IF_NIL(clientId);
    
    if (!(self = [super init]))
        return nil;
    
    SAFE_ARC_RETAIN(context);
    _context = context;
    _tokenCache = context.tokenCacheStore;
    _redirectUri = [redirectUri adTrimmedString];
    SAFE_ARC_RETAIN(_redirectUri);
    _clientId = [clientId adTrimmedString];
    SAFE_ARC_RETAIN(_clientId);
    _resource = [resource adTrimmedString];
    SAFE_ARC_RETAIN(_resource);
    
    _promptBehavior = AD_PROMPT_AUTO;
    
    // This line is here to suppress a analyzer warning, has no effect
    _allowSilent = NO;
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_context);
    SAFE_ARC_RELEASE(_clientId);
    SAFE_ARC_RELEASE(_redirectUri);
    SAFE_ARC_RELEASE(_identifier);
    SAFE_ARC_RELEASE(_resource);
    SAFE_ARC_RELEASE(_scope);
    SAFE_ARC_RELEASE(_queryParams);
    SAFE_ARC_RELEASE(_refreshTokenCredential);
    SAFE_ARC_RELEASE(_correlationId);
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
    if (_identifier == identifier)
    {
        return;
    }
    SAFE_ARC_RELEASE(_identifier);
    _identifier = identifier;
    SAFE_ARC_RETAIN(_identifier);
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
    if (_correlationId == correlationId)
    {
        return;
    }
    SAFE_ARC_RELEASE(_correlationId);
    _correlationId = correlationId;
    SAFE_ARC_RETAIN(_correlationId);
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
    if (_correlationId == nil)
    {
        //if correlationId is set in context, use it
        //if not, generate one
        if ([_context correlationId])
        {
            _correlationId = [_context correlationId];
            SAFE_ARC_RETAIN(_correlationId);
        } else {
            _correlationId = [NSUUID UUID];
            SAFE_ARC_RETAIN(_correlationId);
        }
    }
    
    return _correlationId;
}

/*!
    Takes the UI interaction lock for the current request, will send an error
    to completionBlock if it fails.
 
    @param copmletionBlock  the ADAuthenticationCallback to send an error to if
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
                                                                             correlationId:_correlationId];
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
