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


#import "ADAL.h"
#import "ADAuthenticationRequest.h"
#import "ADInstanceDiscovery.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "NSDictionary+ADExtensions.h"
#import "NSString+ADHelperMethods.h"
#import "NSURL+ADExtensions.h"
#import "ADBrokerKeyHelper.h"
#import "ADAuthenticationRequest+WebRequest.h"

#include <libkern/OSAtomic.h>

@implementation ADAuthenticationRequest

#define RETURN_IF_NIL(_X) { if (!_X) { AD_LOG_ERROR(@#_X " must not be nil!", AD_FAILED, nil); return nil; } }
#define ERROR_RETURN_IF_NIL(_X) { \
    if (!_X) { \
        if (error) { \
            *error = [ADAuthenticationError errorFromArgument:_X argumentName:@#_X]; \
        } \
        return nil; \
    } \
}


+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                   redirectUri:(NSString*)redirectUri
                                      clientId:(NSString*)clientId
                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    ERROR_RETURN_IF_NIL(context);
    ERROR_RETURN_IF_NIL(clientId);
    
    return [[self.class alloc] initWithContext:context redirectUri:redirectUri clientId:clientId];
}

- (id)initWithContext:(ADAuthenticationContext*)context
          redirectUri:(NSString*)redirectUri
             clientId:(NSString*)clientId
{
    RETURN_IF_NIL(context);
    RETURN_IF_NIL(clientId);
    
    if (!(self = [super init]))
        return nil;
    
    _context = context;
    _redirectUri = [redirectUri adTrimmedString];
    _clientId = [clientId adTrimmedString];
    
    _promptBehavior = AD_PROMPT_AUTO;
    
    // This line is here to suppress a analyzer warning, has no effect
    _allowSilent = NO;
    
    return self;
}

#define CHECK_REQUEST_STARTED { \
    if (_requestStarted) { \
        NSString* _details = [NSString stringWithFormat:@"call to %s after the request started. call has no effect.", __PRETTY_FUNCTION__]; \
        AD_LOG_WARN(_details, nil); \
        return; \
    } \
}

- (void)setScopes:(NSArray *)scopes
{
    CHECK_REQUEST_STARTED;
    _scopes = [NSSet setWithArray:scopes];
}

- (void)setAdditionalScopes:(NSArray *)additionalScopes
{
    CHECK_REQUEST_STARTED;
    _additionalScopes = [NSSet setWithArray:additionalScopes];
}

- (void)setPolicy:(NSString *)policy
{
    CHECK_REQUEST_STARTED;
    _policy = policy;
}

- (void)setExtraQueryParameters:(NSString *)queryParams
{
    CHECK_REQUEST_STARTED;
    _queryParams = queryParams;
}

- (void)setUserIdentifier:(ADUserIdentifier *)identifier
{
    CHECK_REQUEST_STARTED;
    _identifier = identifier;
}

- (void)setUserId:(NSString *)userId
{
    CHECK_REQUEST_STARTED;
    _identifier = [ADUserIdentifier identifierWithId:userId];
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

#if AD_BROKER
- (void)setAllowSilentRequests:(BOOL)allowSilent
{
    CHECK_REQUEST_STARTED;
    _allowSilent = allowSilent;
}
#endif

- (void)ensureRequest
{
    if (_requestStarted)
    {
        return;
    }
    
    if (!_correlationId)
    {
        _correlationId = [ADLogger getCorrelationId];
    }
    
    _requestStarted = YES;
}

- (ADTokenCacheStoreKey*)cacheStoreKey:(ADAuthenticationError* __autoreleasing *)error
{
    NSString* userId = nil;
    NSString* uniqueId = nil;
    
    switch (_identifier.type)
    {
        case OptionalDisplayableId:
        case RequiredDisplayableId:
            userId = _identifier.userId;
            break;
        case UniqueId:
            uniqueId = _identifier.userId;
            break;
    }
    
    return [ADTokenCacheStoreKey keyWithAuthority:_context.authority
                                         clientId:_clientId
                                           userId:userId
                                         uniqueId:uniqueId
                                           idType:_identifier.type
                                           scopes:_scopes
                                            error:error];
}

@end
