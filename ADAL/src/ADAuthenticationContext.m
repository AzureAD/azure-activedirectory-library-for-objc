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
#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADWebAuthController.h"
#import "ADAuthenticationSettings.h"
#import "NSURL+ADExtensions.h"
#import "NSDictionary+ADExtensions.h"
#import "ADWebRequest.h"
#import "ADWebResponse.h"
#import "ADInstanceDiscovery.h"
#import "ADTokenCacheItem.h"
#import "ADTokenCacheKey.h"
#import "ADUserInformation.h"
#import "ADWorkPlaceJoin.h"
#import "ADPkeyAuthHelper.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADBrokerKeyHelper.h"
#import "ADClientMetrics.h"
#import "NSString+ADHelperMethods.h"
#import "ADHelpers.h"
#import "ADBrokerNotificationManager.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCache+Internal.h"
#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#endif 
#import "ADTokenCacheAccessor.h"

#import "ADAuthenticationContext+Internal.h"

typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

@implementation ADAuthenticationContext

@synthesize authority = _authority;
@synthesize validateAuthority = _validateAuthority;
@synthesize correlationId = _correlationId;
@synthesize credentialsType = _credentialsType;
@synthesize webView = _webView;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

#if TARGET_OS_IPHONE
- (id)initWithAuthority:(NSString*) authority
      validateAuthority:(BOOL)bValidate
            sharedGroup:(NSString*)sharedGroup
                  error:(ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    NSString* extractedAuthority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = extractedAuthority;
    _validateAuthority = bValidate;
    _credentialsType = AD_CREDENTIALS_EMBEDDED;
    
    _tokenCacheStore = [[ADKeychainTokenCache alloc] initWithGroup:sharedGroup];
    
    return self;
}
#endif

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(ADTokenCache*)tokenCache
                  error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    NSString* extractedAuthority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = extractedAuthority;
    _validateAuthority = validateAuthority;
    _credentialsType = AD_CREDENTIALS_EMBEDDED;
    _tokenCacheStore = tokenCache;
    
    return self;
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
          cacheDelegate:(id<ADTokenCacheDelegate>) delegate
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    ADTokenCache* cache = [ADTokenCache new];
    [cache setDelegate:delegate];
    
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                        tokenCache:cache
                             error:error];
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
                  error:(ADAuthenticationError *__autoreleasing *)error
{
#if TARGET_OS_IPHONE
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                       sharedGroup:[[ADAuthenticationSettings sharedInstance] defaultKeychainGroup]
                             error:error];
#else
    return [self initWithAuthority:authority validateAuthority:validateAuthority cacheDelegate:[ADAuthenticationSettings sharedInstance].defaultCacheDelegate error:error];
#endif
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_authority);
    SAFE_ARC_RELEASE(_tokenCacheStore);
    
    SAFE_ARC_SUPER_DEALLOC();
}

- (ADAuthenticationRequest*)requestWithRedirectString:(NSString*)redirectUri
                                             clientId:(NSString*)clientId
                                             resource:(NSString*)resource
                                      completionBlock:(ADAuthenticationCallback)completionBlock

{
    ADAuthenticationError* error = nil;
    
    ADAuthenticationRequest* request = [ADAuthenticationRequest requestWithContext:self
                                                                       redirectUri:redirectUri
                                                                          clientId:clientId
                                                                          resource:resource
                                                                             error:&error];
    
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
    
    return SAFE_ARC_AUTORELEASE([[self alloc] initWithAuthority:authority validateAuthority:bValidate error:error]);
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
#endif // TARGET_OS_IPHONE

+ (BOOL)isResponseFromBroker:(NSString*)sourceApplication
                    response:(NSURL*)response
{
    return //sourceApplication && [NSString adSame:sourceApplication toString:brokerAppIdentifier];
    response &&
    [NSString adSame:sourceApplication toString:@"com.microsoft.azureauthenticator"];
}

+ (void)handleBrokerResponse:(NSURL*)response
{
    [ADAuthenticationRequest internalHandleBrokerResponse:response];
}

#define REQUEST_WITH_REDIRECT_STRING(_redirect, _clientId, _resource) \
    ADAuthenticationRequest* request = [self requestWithRedirectString:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; }

#define REQUEST_WITH_REDIRECT_URL(_redirect, _clientId, _resource) \
    ADAuthenticationRequest* request = [self requestWithRedirectUrl:_redirect clientId:_clientId resource:_resource completionBlock:completionBlock]; \
    if (!request) { return; }

- (void)acquireTokenForAssertion:(NSString*)assertion
                   assertionType:(ADAssertionType)assertionType
                        resource:(NSString*)resource
                        clientId:(NSString*)clientId
                          userId:(NSString*)userId
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_STRING(nil, clientId, resource);
    [request setUserId:userId];
    
    [request acquireTokenForAssertion:assertion
                        assertionType:assertionType
                      completionBlock:completionBlock];
    
}


- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request acquireToken:completionBlock];
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
    [request acquireToken:completionBlock];
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
    [request acquireToken:completionBlock];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setSilent:YES];
    [request acquireToken:completionBlock];
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
    [request acquireToken:completionBlock];
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
    [request acquireToken:completionBlock];
}

- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                          clientId:(NSString*)clientId
                       redirectUri:(NSString*)redirectUri
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_STRING(redirectUri, clientId, nil);
    
    [request acquireTokenByRefreshToken:refreshToken
                              cacheItem:nil
                        completionBlock:completionBlock];
}

- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                          clientId:(NSString*)clientId
                       redirectUri:(NSString*)redirectUri
                          resource:(NSString*)resource
                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_STRING(redirectUri, clientId, resource);
    
    [request acquireTokenByRefreshToken:refreshToken
                              cacheItem:nil
                        completionBlock:completionBlock];
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
    [request acquireToken:completionBlock];
}

@end

@implementation ADAuthenticationContext (CacheStorage)

- (void)setTokenCacheStore:(id<ADTokenCacheAccessor>)tokenCacheStore
{
    _tokenCacheStore = tokenCacheStore;
}

- (id<ADTokenCacheAccessor>)tokenCacheStore
{
    return _tokenCacheStore;
}

@end

