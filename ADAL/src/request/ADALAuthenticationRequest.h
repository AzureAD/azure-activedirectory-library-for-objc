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
#import "ADALAuthenticationContext.h"
#import "ADALRequestParameters.h"

@class ADALUserIdentifier;
@class MSIDLegacyTokenCacheAccessor;

#define AD_REQUEST_CHECK_ARGUMENT(_arg) { \
    if (!_arg || ([_arg isKindOfClass:[NSString class]] && [(NSString*)_arg isEqualToString:@""])) { \
        NSString* _details = @#_arg " must not be nil!"; \
        completionBlock([ADALAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

#define AD_REQUEST_CHECK_PROPERTY(_property) { \
    if (!_property || ([_property isKindOfClass:[NSString class]] && [(NSString*)_property isEqualToString:@""])) { \
        NSString* _details = @#_property " must not be nil!";\
        completionBlock([ADALAuthenticationResult resultFromParameterError:_details]); \
        return; \
    } \
}

@interface ADALAuthenticationRequest : NSObject <MSIDRequestContext>
{
@protected
    ADALAuthenticationContext* _context;
    ADALRequestParameters* _requestParams;
    
    ADALPromptBehavior _promptBehavior;

    NSString* _refreshTokenCredential;
    
    NSString* _samlAssertion;
    ADALAssertionType _assertionType;
    
    BOOL _silent;
    BOOL _skipCache;
    
    NSString* _logComponent;
    
    BOOL _requestStarted;
    BOOL _attemptedFRT;
    
    ADALTokenCacheItem* _mrrtItem;
    
    ADALAuthenticationError* _underlyingError;
    
    NSString *_cloudAuthority;
    
    NSString *_refreshToken;
    NSString *_claims;
}

@property (nonatomic, readonly) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) NSString *sharedGroup;

@property (retain) NSString* logComponent;
@property (nonatomic, readonly) NSDictionary *appRequestMetadata;

// The default constructor. For requestParams, redirectUri, clientId and resource are mandatory
+ (ADALAuthenticationRequest*)requestWithContext:(ADALAuthenticationContext*)context
                                 requestParams:(ADALRequestParameters*)requestParams
                                    tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
                                         error:(ADALAuthenticationError* __autoreleasing *)error;

// This message is sent before any stage of processing is done, it marks all the fields as un-editable and grabs the
// correlation ID from the logger
- (void)ensureRequest;

// These can only be set before the request gets sent out.
- (void)setScopesString:(NSString*)scopesString;
- (void)setExtraQueryParameters:(NSString*)queryParams;
- (BOOL)setClaims:(NSString *)claims error:(ADALAuthenticationError **)error;
- (void)setUserIdentifier:(ADALUserIdentifier*)identifier;
- (void)setUserId:(NSString*)userId;
- (void)setPromptBehavior:(ADALPromptBehavior)promptBehavior;
- (void)setSilent:(BOOL)silent;
- (void)setSkipCache:(BOOL)skipCache;
- (void)setForceRefresh:(BOOL)forceRefresh;
- (void)setCorrelationId:(NSUUID*)correlationId;
- (NSUUID*)correlationId;
- (NSString*)telemetryRequestId;
- (ADALRequestParameters*)requestParams;
#if AD_BROKER
- (NSString*)redirectUri;
- (void)setRedirectUri:(NSString*)redirectUri;
- (void)setRefreshTokenCredential:(NSString*)refreshTokenCredential;
#endif
- (void)setSamlAssertion:(NSString*)samlAssertion;
- (void)setAssertionType:(ADALAssertionType)assertionType;
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
+ (ADALAuthenticationRequest*)currentModalRequest;

@end

#import "ADALAuthenticationRequest+AcquireAssertion.h"
#import "ADALAuthenticationRequest+AcquireToken.h"
#import "ADALAuthenticationRequest+Broker.h"
#import "ADALAuthenticationRequest+WebRequest.h"
