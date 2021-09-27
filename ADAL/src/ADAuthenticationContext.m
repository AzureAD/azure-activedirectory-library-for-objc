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

#import "ADAuthenticationSettings.h"
#import "ADRequestParameters.h"
#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#import "MSIDKeychainTokenCache.h"
#else
#import "ADTokenCache.h"
#import "ADTokenCache+Internal.h"
#endif 

#import "ADAuthenticationContext+Internal.h"
#import "ADTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "ADTelemetryAPIEvent.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheItem.h"
#import "ADAuthenticationRequest+Broker.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "ADHelpers.h"
#import "MSIDMacTokenCache.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDDefaultTokenCacheAccessor.h"
#import "MSIDAADV1Oauth2Factory.h"

#if MS_REMOTE_PKEYAUTH_CALLBACK && TARGET_OS_SIMULATOR
#import "ADAuthenticationContext+RemoteDeviceIdentity.h"
#endif

// This variable is purposefully a global so that way we can more easily pull it out of the
// symbols in a binary to detect what version of ADAL is being used without needing to
// run the application.
NSString* ADAL_VERSION_VAR = @ADAL_VERSION_STRING;

@interface ADAuthenticationContext()

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
#if !TARGET_OS_IPHONE
// It is used only for delegate proxy purposes between legacy mac delegate and msdi mac delegate.
@property (nonatomic) ADTokenCache *legacyMacCache;
#endif
// iOS keychain group.
@property (nonatomic) NSString *sharedGroup;

@end

@implementation ADAuthenticationContext

@synthesize authority = _authority;
@synthesize validateAuthority = _validateAuthority;
@synthesize correlationId = _correlationId;
@synthesize credentialsType = _credentialsType;
@synthesize extendedLifetimeEnabled = _extendedLifetimeEnabled;
@synthesize logComponent = _logComponent;
@synthesize webView = _webView;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

#if TARGET_OS_IPHONE
- (id)initWithAuthority:(NSString *) authority
      validateAuthority:(BOOL)bValidate
            sharedGroup:(NSString *)sharedGroup
                  error:(ADAuthenticationError *__autoreleasing *) error
{
    API_ENTRY;
    
    self.sharedGroup = sharedGroup;
    id<MSIDTokenCacheDataSource> tokenCacheDataSource;
#if MS_REMOTE_PKEYAUTH_CALLBACK && TARGET_OS_SIMULATOR
    if ([ADAuthenticationContext isInMemoryTokenCacheEnabled])
    {
        tokenCacheDataSource = [MSIDMacTokenCache defaultCache];
    }
    else
    {
    MSIDKeychainTokenCache *keychainTokenCache = [[MSIDKeychainTokenCache alloc] initWithGroup:sharedGroup];
        tokenCacheDataSource = keychainTokenCache;
    // In case if sharedGroup is nil, keychainTokenCache.keychainGroup will return default group.
    // Note: it is in the following format: <team id>.<sharedGroup>
        [self setSharedGroup:[keychainTokenCache keychainGroup]];
    }
#else
    MSIDKeychainTokenCache *keychainTokenCache = [[MSIDKeychainTokenCache alloc] initWithGroup:sharedGroup];
    tokenCacheDataSource = keychainTokenCache;
    // In case if sharedGroup is nil, keychainTokenCache.keychainGroup will return default group.
    // Note: it is in the following format: <team id>.<sharedGroup>
    [self setSharedGroup:[keychainTokenCache keychainGroup]];
#endif
    MSIDLegacyTokenCacheAccessor *tokenCache = [self createIosCache:tokenCacheDataSource];
    
    return [self initWithAuthority:authority
                 validateAuthority:bValidate
                        tokenCache:tokenCache
                             error:error];
}
#else
- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
          cacheDelegate:(id<ADTokenCacheDelegate>) delegate
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    API_ENTRY;
    
    self.legacyMacCache = [ADTokenCache new];
    self.legacyMacCache.delegate = delegate;

    MSIDLegacyTokenCacheAccessor *tokenCache = [self createMacCache:self.legacyMacCache.macTokenCache];
    
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                        tokenCache:tokenCache
                             error:error];
}
#endif

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
                  error:(ADAuthenticationError *__autoreleasing *)error
{
    MSIDLegacyTokenCacheAccessor *tokenCache = nil;

#if TARGET_OS_IPHONE
#if MS_REMOTE_PKEYAUTH_CALLBACK && TARGET_OS_SIMULATOR
    if ([ADAuthenticationContext isInMemoryTokenCacheEnabled])
    {
        tokenCache = [self createIosCache:[MSIDMacTokenCache defaultCache]];
    }
    else
    {
        tokenCache = [self createIosCache:[MSIDKeychainTokenCache defaultKeychainCache]];
        self.sharedGroup = MSIDKeychainTokenCache.defaultKeychainGroup;
    }
#else
    tokenCache = [self createIosCache:[MSIDKeychainTokenCache defaultKeychainCache]];
    [self setSharedGroup:[MSIDKeychainTokenCache defaultKeychainGroup]];
#endif
    
#else
    self.legacyMacCache = [ADTokenCache defaultCache];
    tokenCache = [self createMacCache:self.legacyMacCache.macTokenCache];
#endif
    
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                        tokenCache:tokenCache
                             error:error];
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache
                  error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSString* extractedAuthority = [ADHelpers canonicalizeAuthority:authority];
    if (!extractedAuthority)
    {
        RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    }
    
    _authority = extractedAuthority;
    _validateAuthority = validateAuthority;
    _credentialsType = AD_CREDENTIALS_EMBEDDED;
    _extendedLifetimeEnabled = NO;
    _tokenCache = tokenCache;
    
    return self;
}

- (ADAuthenticationRequest*)requestWithRedirectString:(NSString*)redirectUri
                                             clientId:(NSString*)clientId
                                             resource:(NSString*)resource
                                      completionBlock:(ADAuthenticationCallback)completionBlock

{
    ADAuthenticationError* error = nil;
    
    ADRequestParameters* requestParams = [[ADRequestParameters alloc] init];
    [requestParams setAuthority:_authority];
    [requestParams setResource:resource];
    [requestParams setClientId:clientId];
    [requestParams setRedirectUri:redirectUri];
    [requestParams setExtendedLifetime:_extendedLifetimeEnabled];
    [requestParams setLogComponent:_logComponent];
    [requestParams setClientCapabilities:_clientCapabilities];

    ADAuthenticationRequest *request = [ADAuthenticationRequest requestWithContext:self
                                                                     requestParams:requestParams
                                                                        tokenCache:self.tokenCache
                                                                             error:&error];
    request.sharedGroup = self.sharedGroup;
    
    if (!request)
    {
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]);
    }
    
    return request;
}

- (ADAuthenticationRequest*)requestWithRedirectUrl:(NSURL*)redirectUri
                                          clientId:(NSString*)clientId
                                          resource:(NSString*)resource
                                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    return [self requestWithRedirectString:[redirectUri absoluteString]
                                  clientId:clientId
                                  resource:resource
                           completionBlock:completionBlock];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                              error:error];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:bValidate
                                                                                    error:error];
    if (!context)
    {
        
        return nil;
    }
    return context;
}

#if TARGET_OS_IPHONE
+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                                   sharedGroup:(NSString*)sharedGroup
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                        sharedGroup:sharedGroup
                                              error:error];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                                   sharedGroup:(NSString*)sharedGroup
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    return [[self alloc] initWithAuthority:authority
                         validateAuthority:bValidate
                               sharedGroup:sharedGroup
                                     error:error];
}

+ (BOOL)handleADALResponse:(nonnull NSURL *)response sourceApplication:(nullable NSString *)sourceApplication
{
    if ([ADAuthenticationContext canHandleResponse:response sourceApplication:sourceApplication])
    {
        return [ADAuthenticationContext handleBrokerResponse:response sourceApplication:sourceApplication];
    }
    
    return NO;
}

#endif // TARGET_OS_IPHONE

#define REQUEST_WITH_REDIRECT_STRING(_redirect, _clientId, _resource) \
    THROW_ON_NIL_ARGUMENT(completionBlock) \
    CHECK_STRING_ARG_BLOCK(_clientId) \
    ADAuthenticationRequest* request = [self requestWithRedirectString:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; } \
    [request setLogComponent:_logComponent];

#define REQUEST_WITH_REDIRECT_URL(_redirect, _clientId, _resource) \
    THROW_ON_NIL_ARGUMENT(completionBlock) \
    CHECK_STRING_ARG_BLOCK(_clientId) \
    ADAuthenticationRequest* request = [self requestWithRedirectUrl:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; } \
    [request setLogComponent:_logComponent];

#define CHECK_STRING_ARG_BLOCK(_arg) \
    if ([NSString msidIsStringNilOrBlank:_arg]) { \
        ADAuthenticationError* error = [ADAuthenticationError invalidArgumentError:@#_arg " cannot be nil" correlationId:_correlationId]; \
        completionBlock([ADAuthenticationResult resultFromError:error correlationId:_correlationId]); \
        return; \
    }

- (void)acquireTokenForAssertion:(NSString*)assertion
                   assertionType:(ADAssertionType)assertionType
                        resource:(NSString*)resource
                        clientId:(NSString*)clientId
                          userId:(NSString*)userId
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_STRING(nil, clientId, resource);
    CHECK_STRING_ARG_BLOCK(assertion);
    CHECK_STRING_ARG_BLOCK(resource);
    
    [request setUserId:userId];
    [request setSamlAssertion:assertion];
    [request setAssertionType:assertionType];
    
    [request acquireToken:@"6" completionBlock:completionBlock];
    
}


- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request acquireToken:@"118" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                          userId:(NSString*)userId
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    
    [request acquireToken:@"121" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                          userId:(NSString*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setExtraQueryParameters:queryParams];
    
    [request acquireToken:@"124" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    [request setSilent:YES];
    
    [request acquireToken:@"7" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                                userId:(NSString*)userId
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setSilent:YES];
    
    [request acquireToken:@"8" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString *)resource
                              clientId:(NSString *)clientId
                           redirectUri:(NSURL *)redirectUri
                                userId:(NSString *)userId
                          forceRefresh:(BOOL)forceRefresh
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setSilent:YES];
    [request setForceRefresh:forceRefresh];
    [request acquireToken:@"9" completionBlock:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString *)resource
                              clientId:(NSString *)clientId
                           redirectUri:(NSURL *)redirectUri
                                userId:(NSString *)userId
                                claims:(NSString *)claims
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);

    [request setUserId:userId];
    [request setSilent:YES];
    ADAuthenticationError *claimsError;
    if (![request setClaims:claims error:&claimsError])
    {
        completionBlock([ADAuthenticationResult resultFromError:claimsError correlationId:_correlationId]);
        return;
    }
    [request acquireToken:@"10" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                          userId:(NSString*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setUserId:userId];
    [request setPromptBehavior:promptBehavior];
    [request setExtraQueryParameters:queryParams];
    
    [request acquireToken:@"127" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                  userIdentifier:(ADUserIdentifier*)userId
            extraQueryParameters:(NSString*)queryParams
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setPromptBehavior:promptBehavior];
    [request setUserIdentifier:userId];
    [request setExtraQueryParameters:queryParams];
    
    [request acquireToken:@"130" completionBlock:completionBlock];
}

- (void)acquireTokenWithResource:(NSString *)resource
                        clientId:(NSString *)clientId
                     redirectUri:(NSURL *)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                  userIdentifier:(ADUserIdentifier *)userId
            extraQueryParameters:(NSString *)queryParams
                          claims:(NSString *)claims
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setPromptBehavior:promptBehavior];
    [request setUserIdentifier:userId];
    [request setExtraQueryParameters:queryParams];
    
    ADAuthenticationError *claimsError;
    if (![request setClaims:claims error:&claimsError])
    {
        completionBlock([ADAuthenticationResult resultFromError:claimsError correlationId:_correlationId]);
        return;
    }
        
    [request acquireToken:@"133" completionBlock:completionBlock];
}

- (void)acquireTokenWithRefreshToken:(NSString *)refreshToken
                            resource:(NSString *)resource
                            clientId:(NSString *)clientId
                         redirectUri:(NSURL *)redirectUri
                     completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    CHECK_STRING_ARG_BLOCK(refreshToken);
    [request setRefreshToken:refreshToken];
    [request setScopesString:MSID_OAUTH2_SCOPE_OPENID_VALUE];
    [request setSilent:YES];
    
    [request acquireToken:@"136" completionBlock:completionBlock];
}

- (void)acquireTokenWithRefreshToken:(NSString *)refreshToken
                            resource:(NSString *)resource
                            clientId:(NSString *)clientId
                         redirectUri:(NSURL *)redirectUri
                              userId:(NSString *)userId
                     completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    CHECK_STRING_ARG_BLOCK(refreshToken);
    [request setRefreshToken:refreshToken];
    [request setUserId:userId];
    [request setScopesString:MSID_OAUTH2_SCOPE_OPENID_VALUE];
    [request setSilent:YES];
    
    [request acquireToken:@"137" completionBlock:completionBlock];
}

- (void)acquireTokenInteractiveWithResource:(NSString *)resource
                        clientId:(NSString *)clientId
                     redirectUri:(NSURL *)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                  userIdentifier:(ADUserIdentifier *)userId
            extraQueryParameters:(NSString *)queryParams
                          claims:(NSString *)claims
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);

    [request setPromptBehavior:promptBehavior];
    [request setUserIdentifier:userId];
    [request setExtraQueryParameters:queryParams];
    [request setSkipCache:YES];

    ADAuthenticationError *claimsError;
    if (![request setClaims:claims error:&claimsError])
    {
        completionBlock([ADAuthenticationResult resultFromError:claimsError correlationId:_correlationId]);
        return;
    }

    [request acquireToken:@"138" completionBlock:completionBlock];
}

#pragma mark - Private

#if TARGET_OS_IPHONE
- (MSIDLegacyTokenCacheAccessor *)createIosCache:(id<MSIDTokenCacheDataSource>)dataSource
{
    MSIDOauth2Factory *factory = [MSIDAADV1Oauth2Factory new];
    MSIDDefaultTokenCacheAccessor *defaultAccessor = [[MSIDDefaultTokenCacheAccessor alloc] initWithDataSource:dataSource otherCacheAccessors:nil factory:factory];
    MSIDLegacyTokenCacheAccessor *legacyAccessor = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:dataSource otherCacheAccessors:@[defaultAccessor] factory:factory];
    return legacyAccessor;
}
#else
- (MSIDLegacyTokenCacheAccessor *)createMacCache:(id<MSIDTokenCacheDataSource>)dataSource
{
    return [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:dataSource otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
}
#endif

@end
