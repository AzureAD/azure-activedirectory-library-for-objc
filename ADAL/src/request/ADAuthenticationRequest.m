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
#import "ADBrokerKeyHelper.h"
#import "ADAuthenticationRequest+WebRequest.h"
#import "ADUserIdentifier.h"

#include <libkern/OSAtomic.h>

@implementation ADAuthenticationRequest

@synthesize component = _component;

#define RETURN_IF_NIL(_X) { if (!_X) { AD_LOG_ERROR(@#_X " must not be nil!", AD_FAILED, nil, nil); SAFE_ARC_RELEASE(self); return nil; } }
#define ERROR_RETURN_IF_NIL(_X) { \
    if (!_X) { \
        if (error) { \
            *error = [ADAuthenticationError errorFromArgument:_X argumentName:@#_X correlationId:context.correlationId]; \
        } \
        return nil; \
    } \
}


+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                   redirectUri:(NSString*)redirectUri
                                      clientId:(NSString*)clientId
                                      resource:(NSString*)resource
                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL(clientId);
    
    return SAFE_ARC_AUTORELEASE([[ADAuthenticationRequest alloc] initWithContext:context redirectUri:redirectUri clientId:clientId resource:resource]);
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
    SAFE_ARC_RELEASE(_scope);
    _scope = scope;
    SAFE_ARC_RETAIN(_scope);
}

- (void)setExtraQueryParameters:(NSString *)queryParams
{
    CHECK_REQUEST_STARTED;
    SAFE_ARC_RELEASE(_queryParams);
    _queryParams = queryParams;
    SAFE_ARC_RETAIN(_queryParams);
}

- (void)setUserIdentifier:(ADUserIdentifier *)identifier
{
    CHECK_REQUEST_STARTED;
    SAFE_ARC_RELEASE(_identifier);
    _identifier = identifier;
    SAFE_ARC_RETAIN(_identifier);
}

- (void)setUserId:(NSString *)userId
{
    CHECK_REQUEST_STARTED;
    SAFE_ARC_RELEASE(_identifier);
    _identifier = [ADUserIdentifier identifierWithId:userId];
    SAFE_ARC_RETAIN(_identifier);
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
    SAFE_ARC_RELEASE(_redirectUri);
    _redirectUri = redirectUri;
    SAFE_ARC_RETAIN(_redirectUri);
}

- (void)setAllowSilentRequests:(BOOL)allowSilent
{
    CHECK_REQUEST_STARTED;
    _allowSilent = allowSilent;
}

- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential
{
    CHECK_REQUEST_STARTED;
    SAFE_ARC_RELEASE(_refreshTokenCredential);
    _refreshTokenCredential = refreshTokenCredential;
    SAFE_ARC_RETAIN(_refreshTokenCredential);
}
#endif

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

@end
