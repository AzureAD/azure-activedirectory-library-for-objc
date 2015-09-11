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

#import "ADALiOS.h"
#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationSettings.h"
#import "NSURL+ADExtensions.h"
#import "NSDictionary+ADExtensions.h"
#import "ADWebRequest.h"
#import "ADWebResponse.h"
#import "ADInstanceDiscovery.h"
#import "ADTokenCacheStoreItem.h"
#import "ADTokenCacheStoreKey.h"
#import "ADProfileInfo.h"
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

#import "ADAuthenticationContext+Internal.h"

#import <objc/runtime.h>


#if BROKER_ENABLED
typedef BOOL (*applicationOpenURLPtr)(id, SEL, UIApplication*, NSURL*, NSString*, id);
IMP __original_ApplicationOpenURL = NULL;

BOOL __swizzle_ApplicationOpenURL(id self, SEL _cmd, UIApplication* application, NSURL* url, NSString* sourceApplication, id annotation)
{
    if (![ADAuthenticationContext isResponseFromBroker:sourceApplication response:url])
    {
        if (__original_ApplicationOpenURL)
            return ((applicationOpenURLPtr)__original_ApplicationOpenURL)(self, _cmd, application, url, sourceApplication, annotation);
        else
            return NO;
    }
    
    [ADAuthenticationContext handleBrokerResponse:url];
    return YES;
}
#endif // BROKER_ENABLED


typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);

@implementation ADAuthenticationContext

#if BROKER_ENABLED
+ (void) load
{
    __block id observer = nil;
    
    observer = [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                                 object:nil
                                                                  queue:nil
                                                             usingBlock:^(NSNotification* notification)
                {
                    // We don't want to swizzle multiple times so remove the observer
                    [[NSNotificationCenter defaultCenter] removeObserver:observer name:UIApplicationDidFinishLaunchingNotification object:nil];
                    
                    SEL sel = @selector(application:openURL:sourceApplication:annotation:);
                    
                    // Dig out the app delegate (if there is one)
                    __strong id appDelegate = [[UIApplication sharedApplication] delegate];
                    
                    // There's not much we can do if there's no app delegate and there might be scenarios where
                    // that is valid...
                    if (appDelegate == nil)
                        return;
                    
                    if ([appDelegate respondsToSelector:sel])
                    {
                        Method m = class_getInstanceMethod([appDelegate class], sel);
                        __original_ApplicationOpenURL = method_getImplementation(m);
                        method_setImplementation(m, (IMP)__swizzle_ApplicationOpenURL);
                    }
                    else
                    {
                        NSString* typeEncoding = [NSString stringWithFormat:@"%s%s%s%s%s%s%s", @encode(BOOL), @encode(id), @encode(SEL), @encode(UIApplication*), @encode(NSURL*), @encode(NSString*), @encode(id)];
                        class_addMethod([appDelegate class], sel, (IMP)__swizzle_ApplicationOpenURL, [typeEncoding UTF8String]);
                        
                        // UIApplication caches whether or not the delegate responds to certain selectors. Clearing out the delegate and resetting it gaurantees that gets updated
                        [[UIApplication sharedApplication] setDelegate:nil];
                        // UIApplication employs dark magic to assume ownership of the app delegate when it gets the app delegate at launch, it won't do that for setDelegate calls so we
                        // have to add a retain here to make sure it doesn't turn into a zombie
                        [[UIApplication sharedApplication] setDelegate:(__bridge id)CFRetain((__bridge CFTypeRef)appDelegate)];
                    }
                    
                }];
    
}
#endif // BROKER_ENABLED

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithAuthority:(NSString*) authority
      validateAuthority:(BOOL)bValidate
        tokenCacheStore:(id<ADTokenCacheStoring>)tokenCache
                  error:(ADAuthenticationError* __autoreleasing *) error
{
    API_ENTRY;
    NSString* extractedAuthority = [ADInstanceDiscovery canonicalizeAuthority:authority];
    RETURN_ON_INVALID_ARGUMENT(!extractedAuthority, authority, nil);
    
    self = [super init];
    if (self)
    {
        _authority = extractedAuthority;
        _validateAuthority = bValidate;
        _tokenCacheStore = tokenCache;
    }
    return self;
}


- (ADAuthenticationRequest*)requestWithRedirectString:(NSString*)redirectUri
                                             clientId:(NSString*)clientId
                                      completionBlock:(ADAuthenticationCallback)completionBlock

{
    ADAuthenticationError* error = nil;
    
    ADAuthenticationRequest* request = [ADAuthenticationRequest requestWithContext:self
                                                                       redirectUri:redirectUri
                                                                          clientId:clientId
                                                                             error:&error];
    
    if (!request)
    {
        completionBlock([ADAuthenticationResult resultFromError:error]);
    }
    
    return request;
}

- (ADAuthenticationRequest*)requestWithRedirectUrl:(NSURL*)redirectUri
                                          clientId:(NSString*)clientId
                                   completionBlock:(ADAuthenticationCallback)completionBlock
{
    return [self requestWithRedirectString:[redirectUri absoluteString]
                                  clientId:clientId
                           completionBlock:completionBlock];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                    tokenCacheStore:[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore
                                              error:error];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:bValidate
                                    tokenCacheStore:[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore
                                              error:error];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                               tokenCacheStore:(id<ADTokenCacheStoring>)tokenCache
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    return [self authenticationContextWithAuthority:authority
                                  validateAuthority:YES
                                    tokenCacheStore:tokenCache
                                              error:error];
}

+ (ADAuthenticationContext*)authenticationContextWithAuthority:(NSString*)authority
                                             validateAuthority:(BOOL)bValidate
                                               tokenCacheStore:(id<ADTokenCacheStoring>)tokenCache
                                                         error:(ADAuthenticationError* __autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authority);
    
    return [[self alloc] initWithAuthority: authority
                         validateAuthority: bValidate
                           tokenCacheStore: tokenCache
                                     error: error];
}

#if BROKER_ENABLED
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
#endif // BROKER_ENABLED

#define REQUEST_WITH_REDIRECT_STRING(_redirect, _clientId) \
    ADAuthenticationRequest* request = [self requestWithRedirectString:_redirect clientId:_clientId completionBlock:completionBlock]; \
    if (!request) { return; }

#define REQUEST_WITH_REDIRECT_URL(_redirect, _clientId) \
    ADAuthenticationRequest* request = [self requestWithRedirectUrl:_redirect clientId:_clientId completionBlock:completionBlock]; \
    if (!request) { return; }


/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. If neither of these attempts succeeds, the method will use
    the provided assertion to get an access token from the service.
 
    @param samlAssertion    the assertion representing the authenticated user.
    @param assertionType    the assertion type of the user assertion.
    @param scopes           An array of NSStrings specifying the scopes required for the request
    @param additionalScopes An array of NSStrings of any additional scopes to ask the user consent for
    @param clientId         the client identifier
    @param identifier       A ADUserIdentifier object describing the user being authenticated. This parameter can be nil.
    @param completionBlock: the block to execute upon completion. You can use embedded block, e.g.
                            "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenForAssertion:(NSString*)assertion
                   assertionType:(ADAssertionType)assertionType
                          scopes:(NSArray*)scopes
                additionalScopes:(NSArray*)additionalScopes
                        clientId:(NSString*)clientId
                      identifier:(ADUserIdentifier*)identifier
                 completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"assertion:%lu assertiontype:%@ scopes:%@ additionalscopes:%@ clientId:%@ identifier:%@",
                (unsigned long)[assertion hash], assertionType == AD_SAML1_1 ? @"v1.1" : @"v2.0", scopes, additionalScopes, clientId, identifier);
    REQUEST_WITH_REDIRECT_STRING(nil, clientId);
    
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    CALLBACK_ON_ERROR([request setAdditionalScopes:additionalScopes]);
    [request setUserIdentifier:identifier];
    
    [request acquireTokenForAssertion:assertion
                        assertionType:assertionType
                      completionBlock:completionBlock];
}


/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
    credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
    leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
    UI displaying is desired.

    @param resource: the resource whose token is needed.
    @param clientId: the client identifier
    @param redirectUri: The redirect URI according to OAuth2 protocol.
    @param completionBlock: the block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithScopes:(NSArray*)scopes
             additionalScopes:(NSArray*)additionalScopes
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"scopes:%@ additionalScopes:%@ clientId:%@ redirectUri:%@", scopes, additionalScopes, clientId, redirectUri);
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    CALLBACK_ON_ERROR([request setAdditionalScopes:additionalScopes]);
    
    [request acquireToken:completionBlock];
}


/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
    credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
    leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
    UI displaying is desired.
 
    @param scopes           An array of NSStrings specifying the scopes required for the request
    @param additionalScopes An array of NSStrings of any additional scopes to ask the user consent for
    @param clientId         the client identifier
    @param redirectUri      The redirect URI according to OAuth2 protocol
    @param identifier       A ADUserIdentifier object describing the user being authenticated. This parameter can be nil.
    @param completionBlock  the block to execute upon completion. You can use embedded block, e.g.
                            "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithScopes:(NSArray*)scopes
             additionalScopes:(NSArray*)additionalScopes
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                   identifier:(ADUserIdentifier*)identifier
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"scopes:%@ additionalScopes:%@ clientId:%@ redirectUri:%@ identifier:%@",
                scopes, additionalScopes, clientId, redirectUri, identifier);
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    CALLBACK_ON_ERROR([request setAdditionalScopes:additionalScopes]);
    [request setUserIdentifier:identifier];
    
    [request acquireToken:completionBlock];
}


/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
    credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
    leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
    UI displaying is desired.
 
    @param scopes               An array of NSStrings specifying the scopes required for the request
    @param additionalScopes     An array of NSStrings of any additional scopes to ask the user consent for
    @param clientId             The client identifier
    @param redirectUri          The redirect URI according to OAuth2 protocol
    @param identifier           A ADUserIdentifier object describing the user being authenticated. This parameter can be nil.
    @param extraQueryParameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
    @param completionBlock      the block to execute upon completion. You can use embedded block, e.g.
                                "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithScopes:(NSArray*)scopes
             additionalScopes:(NSArray*)additionalScopes
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                   identifier:(ADUserIdentifier*)identifier
         extraQueryParameters:(NSString*)queryParams
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"scopes:%@ additionalScopes:%@ clientId:%@ redirectUri:%@ identifier:%@ queryParams:%@",
                scopes, additionalScopes, clientId, redirectUri, identifier, queryParams);
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);

    CALLBACK_ON_ERROR([request setScopes:scopes]);
    CALLBACK_ON_ERROR([request setAdditionalScopes:additionalScopes]);
    [request setUserIdentifier:identifier];
    [request setExtraQueryParameters:queryParams];
    [request acquireToken:completionBlock];
}


/*!
    Follows the OAuth2 protocol (RFC 6749). The behavior is controlled by the promptBehavior parameter on whether to re-authorize
    the resource usage (through webview credentials UI) or attempt to use the cached tokens first.
 
    @param scopes               An array of NSStrings specifying the scopes required for the request
    @param additionalScopes     An array of NSStrings of any additional scopes to ask the user consent for
    @param clientId             the client identifier
    @param redirectUri          The redirect URI according to OAuth2 protocol
    @param promptBehavior       controls if any credentials UI will be shown
    @param identifier           A ADUserIdentifier object describing the user being authenticated. This parameter can be nil.
    @param extraQueryParameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
    @param policy               ??????
    @param completionBlock      the block to execute upon completion. You can use embedded block, e.g.
                                "^(ADAuthenticationResult res){ <your logic here> }"
 */

- (void)acquireTokenWithScopes:(NSArray*)scopes
             additionalScopes:(NSArray*)additionalScopes
                     clientId:(NSString*)clientId
                  redirectUri:(NSURL*)redirectUri
                   identifier:(ADUserIdentifier*)identifier
         extraQueryParameters:(NSString*)queryParams
                       policy:(NSString*)policy
              completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"scopes:%@ additionalScopes:%@ clientId:%@ redirectUri:%@ identifier:%@ queryParams:%@ policy:%@",
               scopes, additionalScopes, clientId, redirectUri, identifier, queryParams, policy);
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    CALLBACK_ON_ERROR([request setAdditionalScopes:additionalScopes]);
    [request setUserIdentifier:identifier];
    [request setExtraQueryParameters:queryParams];
    [request setPolicy:policy];
    [ADAuthenticationSettings sharedInstance].policy = policy;
    [request acquireToken:completionBlock];
}


/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
    If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.

    @param scopes           An array of NSString* specifying the scopes required for the request
    @param clientId         the client identifier
    @param redirectUri      The redirect URI according to OAuth2 protocol.
    @param completionBlock  the block to execute upon completion. You can use embedded block, e.g.
                            "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithScopes:(NSArray*)scopes
                           clientId:(NSString*)clientId
                        redirectUri:(NSURL*)redirectUri
                    completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY_F(@"scopes:%@ clientId:%@ redirectUri:%@", scopes, clientId, redirectUri);
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    [request setSilent:YES];
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    [request acquireToken:completionBlock];
}

/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
    If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.

    @param scopes           An array of NSString* specifying the scopes required for the request
    @param clientId         the client identifier
    @param redirectUri      The redirect URI according to OAuth2 protocol
    @param identifier       An ADUserIdentifier object specifying the semantics
    @param completionBlock: the block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithScopes:(NSArray*)scopes
                           clientId:(NSString*)clientId
                        redirectUri:(NSURL*)redirectUri
                         identifier:(ADUserIdentifier*)identifier
                    completionBlock:(ADAuthenticationCallback)completionBlock
{
    
    API_ENTRY_F(@"scopes:%@ clientId:%@ redirectUri:%@ identifier:%@", scopes, clientId, redirectUri, identifier);
    
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    [request setSilent:YES];
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    [request setUserIdentifier:identifier];
    
    [request acquireToken:completionBlock];
}

/*!
    Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
    expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
    the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
    If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.

    @param scopes           An array of NSString* specifying the scopes required for the request
    @param clientId         the client identifier
    @param redirectUri      The redirect URI according to OAuth2 protocol
    @param identifier       An ADUserIdentifier object specifying the semantics
    @param policy           ?????
    @param completionBlock: the block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithScopes:(NSArray*)scopes
                           clientId:(NSString*)clientId
                        redirectUri:(NSURL*)redirectUri
                         identifier:(ADUserIdentifier*)identifier
                             policy:(NSString*)policy
                    completionBlock:(ADAuthenticationCallback)completionBlock
{
    API_ENTRY;
    REQUEST_WITH_REDIRECT_URL(redirectUri, clientId);
    
    
    [request setSilent:YES];
    CALLBACK_ON_ERROR([request setScopes:scopes]);
    [request setUserIdentifier:identifier];
    [request setPolicy:policy];
    
    [request acquireToken:completionBlock];
}

@end

