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


#import <Foundation/Foundation.h>
#import "ADAuthenticationContext.h"
#import "ADRequestParameters.h"

@class ADUserIdentifier;
@class MSIDLegacyTokenCacheAccessor;

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

@interface ADAuthenticationRequest : NSObject <MSIDRequestContext>
{
@protected
    ADAuthenticationContext* _context;
    ADRequestParameters* _requestParams;
    
    ADPromptBehavior _promptBehavior;
    
    NSString* _queryParams;
    NSString* _claims;
    
    NSString* _refreshTokenCredential;
    
    NSString* _samlAssertion;
    ADAssertionType _assertionType;
    
    BOOL _silent;
    BOOL _allowSilent;
    BOOL _skipCache;
    
    NSString* _logComponent;
    
    BOOL _requestStarted;
    BOOL _attemptedFRT;
    
    ADTokenCacheItem* _mrrtItem;
    
    ADAuthenticationError* _underlyingError;
    
    NSString *_cloudAuthority;
    
    NSString *_refreshToken;
}

@property (nonatomic, readonly) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) NSString *sharedGroup;

@property (retain) NSString* logComponent;

// The default constructor. For requestParams, redirectUri, clientId and resource are mandatory
+ (ADAuthenticationRequest*)requestWithContext:(ADAuthenticationContext*)context
                                 requestParams:(ADRequestParameters*)requestParams
                                    tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
                                         error:(ADAuthenticationError* __autoreleasing *)error;

// This message is sent before any stage of processing is done, it marks all the fields as un-editable and grabs the
// correlation ID from the logger
- (void)ensureRequest;

// These can only be set before the request gets sent out.
- (void)setScopesString:(NSString*)scopesString;
- (void)setExtraQueryParameters:(NSString*)queryParams;
- (void)setClaims:(NSString *)claims;
- (void)setUserIdentifier:(ADUserIdentifier*)identifier;
- (void)setUserId:(NSString*)userId;
- (void)setPromptBehavior:(ADPromptBehavior)promptBehavior;
- (void)setSilent:(BOOL)silent;
- (void)setSkipCache:(BOOL)skipCache;
- (void)setCorrelationId:(NSUUID*)correlationId;
- (NSUUID*)correlationId;
- (NSString*)telemetryRequestId;
- (ADRequestParameters*)requestParams;
#if AD_BROKER
- (NSString*)redirectUri;
- (void)setRedirectUri:(NSString*)redirectUri;
- (void)setAllowSilentRequests:(BOOL)allowSilent;
- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential;
#endif
- (void)setSamlAssertion:(NSString*)samlAssertion;
- (void)setAssertionType:(ADAssertionType)assertionType;
- (void)setRefreshToken:(NSString *)refreshToken;

// This can be set anyTime
- (void)setCloudInstanceHostname:(NSString *)cloudInstanceHostName;

/*!
    Takes the UI interaction lock for the current request, will send an error
    to completionBlock if it fails.
 
    @param completionBlock  the ADAuthenticationCallback to send an error to if
                            one occurs.
 
    @return NO if we fail to take the exclusion lock
 */
- (BOOL)takeExclusionLock:(ADAuthenticationCallback)completionBlock;

/*!
    Releases the exclusion lock
 */
+ (void)releaseExclusionLock;

/*!
    The current interactive request ADAL is displaying UI for (if any)
 */
+ (ADAuthenticationRequest*)currentModalRequest;

@end

#import "ADAuthenticationRequest+AcquireAssertion.h"
#import "ADAuthenticationRequest+AcquireToken.h"
#import "ADAuthenticationRequest+Broker.h"
#import "ADAuthenticationRequest+WebRequest.h"
