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


#import <Foundation/Foundation.h>
#import "ADAuthenticationContext.h"

@class ADUserIdentifier;

typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

#define AD_REQUEST_CHECK_ARGUMENT(_arg) { \
    if (!_arg || ([_arg isKindOfClass:[NSString class]] && [(NSString*)_arg isEqualToString:@""])) { \
        NSString* _details = @#_arg " must not be nil!"; \
        completionBlock([ADAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

#define AD_REQUEST_CHECK_PROPERTY(_property) { \
    if (!_property || ([_property isKindOfClass:[NSString class]] && [(NSString*)_property isEqualToString:@""])) { \
        NSString* _details = @#_property " must not be nil!";\
        completionBlock([ADAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

@interface ADAuthenticationRequest : NSObject
{
@protected
    ADAuthenticationContext* _context;
    NSString* _clientId;
    NSString* _redirectUri;
    
    ADUserIdentifier* _identifier;
    
    ADPromptBehavior _promptBehavior;
    
    NSSet* _scopes;
    NSSet* _additionalScopes;
    
    NSString* _policy;
    
    NSString* _queryParams;
    
    BOOL _silent;
    BOOL _allowSilent;
    
    NSUUID* _correlationId;
    
    BOOL _requestStarted;
}

// The default constructor. All of the parameters are mandatory
+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                   redirectUri:(NSString*)redirectUri
                                      clientId:(NSString*)clientId
                                         error:(ADAuthenticationError* __autoreleasing *)error;

// This message is sent before any stage of processing is done, it marks all the fields as un-editable and grabs the
// correlation ID from the logger
- (void)ensureRequest;

// These can only be set before the request gets sent out.
- (void)setScopes:(NSArray*)scopes;
- (void)setAdditionalScopes:(NSArray*)additionalScopes;
- (void)setPolicy:(NSString*)policy;
- (void)setExtraQueryParameters:(NSString*)queryParams;
- (void)setUserIdentifier:(ADUserIdentifier*)identifier;
- (void)setUserId:(NSString*)userId;
- (void)setPromptBehavior:(ADPromptBehavior)promptBehavior;
- (void)setSilent:(BOOL)silent;
#if AD_BROKER
- (void)setAllowSilentRequests:(BOOL)allowSilent;
#endif

- (NSSet*)combinedScopes;

- (ADTokenCacheStoreKey*)cacheStoreKey:(ADAuthenticationError* __autoreleasing *)error;
@end

#import "ADAuthenticationRequest+AcquireAssertion.h"
#import "ADAuthenticationRequest+AcquireToken.h"
#import "ADAuthenticationRequest+Broker.h"
#import "ADAuthenticationRequest+WebRequest.h"
