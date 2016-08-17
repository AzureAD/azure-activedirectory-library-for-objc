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
#import "ADInstanceDiscovery.h"
#import "ADTokenCache+Internal.h"
#import "ADRequestParameters.h"
#if TARGET_OS_IPHONE
#import "ADKeychainTokenCache+Internal.h"
#endif 

#import "ADAuthenticationContext+Internal.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryAPIEvent.h"
#import "ADUserIdentifier.h"

typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

// This variable is purposefully a global so that way we can more easily pull it out of the
// symbols in a binary to detect what version of ADAL is being used without needing to
// run the application.
NSString* ADAL_VERSION_VAR = @ADAL_VERSION_STRING;

@implementation ADAuthenticationContext

@synthesize authority = _authority;
@synthesize validateAuthority = _validateAuthority;
@synthesize correlationId = _correlationId;
@synthesize credentialsType = _credentialsType;
//@synthesize extendedLifetimeEnabled = _extendedLifetimeEnabled; ADAL_RESILIENCY_NOT_YET
@synthesize logComponent = _logComponent;
@synthesize webView = _webView;

+ (void)load
{
    // +load is called by the ObjC runtime before main() as it loads in ObjC symbols and
    // populates the runtime.
    
    NSLog(@"ADAL version %@", ADAL_VERSION_VAR);
}

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
    if (!(self = [self initWithAuthority:authority validateAuthority:bValidate error:error]))
    {
        return nil;
    }
    
    [self setTokenCacheStore:[ADKeychainTokenCache keychainCacheForGroup:sharedGroup]];
    
    return self;
}
#endif

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(id<ADTokenCacheDataSource>)tokenCache
                  error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSString* extractedAuthority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    if (!extractedAuthority)
    {
        SAFE_ARC_RELEASE(self);
        RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    }
    
    _authority = extractedAuthority;
    _validateAuthority = validateAuthority;
    _credentialsType = AD_CREDENTIALS_EMBEDDED;
    _extendedLifetimeEnabled = NO;
    [self setTokenCacheStore:tokenCache];

    return self;
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
          cacheDelegate:(id<ADTokenCacheDelegate>) delegate
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    API_ENTRY;
    if (!(self = [self initWithAuthority:authority validateAuthority:validateAuthority error:error]))
    {
        return nil;
    }
    
    ADTokenCache* cache = [ADTokenCache new];
    [cache setDelegate:delegate];
    
    [self setTokenCacheStore:cache];
    SAFE_ARC_RELEASE(cache);
    return self;
}

- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
                  error:(ADAuthenticationError *__autoreleasing *)error
{
    id<ADTokenCacheDataSource> tokenCache = nil;

#if TARGET_OS_IPHONE
    tokenCache = [ADKeychainTokenCache defaultKeychainCache];
    if (!tokenCache)
    {
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Unable to get kecyhain token cache" correlationId:nil];
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
#else
    tokenCache = [ADTokenCache new];
    [(ADTokenCache*)tokenCache setDelegate:[ADAuthenticationSettings sharedInstance].defaultStorageDelegate];
#endif
    
    return [self initWithAuthority:authority
                 validateAuthority:validateAuthority
                        tokenCache:tokenCache
                             error:error];
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
    
    ADRequestParameters* requestParams = [[ADRequestParameters alloc] init];
    [requestParams setAuthority:_authority];
    [requestParams setResource:resource];
    [requestParams setClientId:clientId];
    [requestParams setRedirectUri:redirectUri];
    [requestParams setTokenCache:_tokenCacheStore];
    [requestParams setExtendedLifetime:_extendedLifetimeEnabled];

    ADAuthenticationRequest* request = [ADAuthenticationRequest requestWithContext:self
                                                                     requestParams:requestParams
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
    
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:bValidate
                                                                                    error:error];
    if (!context)
    {
        
        return nil;
    }
    
    SAFE_ARC_AUTORELEASE(context);
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
    if ([NSString adIsStringNilOrBlank:_arg]) { \
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithAssertion:assertionType:resource:clientId:userId:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithAssertion:assertionType:resource:clientId:userId:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"6"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
    
}


- (void)acquireTokenWithResource:(NSString*)resource
                        clientId:(NSString*)clientId
                     redirectUri:(NSURL*)redirectUri
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithResource:clientId:redirectUri:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithResource:clientId:redirectUri:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"118"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithResource:clientId:redirectUri:userId:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithResource:clientId:redirectUri:userId:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"121"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithResource:clientId:redirectUri:userId:extraQueryParameters:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithResource:clientId:redirectUri:userId:extraQueryParameters:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"124"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
}

- (void)acquireTokenSilentWithResource:(NSString*)resource
                              clientId:(NSString*)clientId
                           redirectUri:(NSURL*)redirectUri
                       completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId, resource);
    
    [request setSilent:YES];
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenSilentWithResource:clientId:redirectId:redirectUri:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenSilentWithResource:clientId:redirectId:redirectUri:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"7"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenSilentWithResource:clientId:redirectId:redirectUri:userId:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenSilentWithResource:clientId:redirectId:redirectUri:userId:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"8"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithResource:clientId:redirectUri:promptBehavior:userId:extraQueryParameters:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithResource:clientId:redirectUri:promptBehavior:userId:extraQueryParameters:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"127"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
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
    
    //prepare telemetry for the acquire token call
    [[ADTelemetry sharedInstance] startEvent:[request telemetryRequestId]
                                   eventName:@"acquireTokenWithResource:clientId:redirectUri:promptBehavior:userIdentifier:extraQueryParameters:completionBlock:"];
    ADAuthenticationCallback requestCompletion = ^void(ADAuthenticationResult *result)
    {
        ADTelemetryAPIEvent* event = [[ADTelemetryAPIEvent alloc] initWithName:@"acquireTokenWithResource:clientId:redirectUri:promptBehavior:userIdentifier:extraQueryParameters:completionBlock:"
                                                                     requestId:[request telemetryRequestId]
                                                                 correlationId:[request correlationId]];
        [event setApiId:@"130"];
        [self fillTelemetryForAcquireTokenCall:event request:request result:result];
        [[ADTelemetry sharedInstance] stopEvent:[request telemetryRequestId] event:event];
        SAFE_ARC_RELEASE(event);
        //flush all events in the end of the acquireToken call
        [[ADTelemetry sharedInstance] flush:[request telemetryRequestId]];
        
        completionBlock(result);
    };
    
    [request acquireToken:requestCompletion];
}

- (void)fillTelemetryForAcquireTokenCall:(ADTelemetryAPIEvent*)event
                                 request:(ADAuthenticationRequest*)request
                                  result:(ADAuthenticationResult*)result
{
    [event setCorrelationId:[request.requestParams correlationId]];
    [event setUserId:[[request.requestParams identifier] userId]];
    [event setClientId:[request.requestParams clientId]];
    [event setResultStatus:[result status]];
    [event setIsExtendedLifeTimeToken:[result extendedLifeTimeToken]? @"YES":@"NO"];
    [event setErrorCode:[NSString stringWithFormat:@"%ld",(long)[result.error code]]];
    [event setErrorDomain:[result.error domain]];
    [event setProtocolCode:[[result error] protocolCode]];
    [event setErrorDescription:[[result error] errorDetails]];
}

@end

@implementation ADAuthenticationContext (CacheStorage)

- (void)setTokenCacheStore:(id<ADTokenCacheDataSource>)dataSource
{
    if (_tokenCacheStore.dataSource == dataSource)
    {
        return;
    }
    
    SAFE_ARC_RELEASE(_tokenCacheStore);
    _tokenCacheStore = [[ADTokenCacheAccessor alloc] initWithDataSource:dataSource authority:_authority];
}

- (ADTokenCacheAccessor *)tokenCacheStore
{
    return _tokenCacheStore;
}

@end

