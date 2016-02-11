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
