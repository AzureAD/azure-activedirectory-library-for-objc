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

@class ADAuthenticationError;
@class ADAuthenticationResult;
@class ADTokenCacheItem;
@class ADUserInformation;
@class ADUserIdentifier;
@class UIViewController;
@class ADTokenCache;

#if !TARGET_OS_IPHONE
@protocol ADTokenCacheDelegate;
#endif

typedef enum
{
    /*! Default option. Assumes the assertion provided is of type SAML 1.1. */
    AD_SAML1_1,
    
    /*! Assumes the assertion provided is of type SAML 2. */
    AD_SAML2,
} ADAssertionType;


typedef enum
{
    /*!
        Default option. Users will be prompted only if their attention is needed. First the cache will
        be checked for a suitable access token (non-expired). If none is found, the cache will be checked
        for a suitable refresh token to be used for obtaining a new access token. If this attempt fails
        too, it depends on the acquireToken method being called.
        acquireTokenWithResource methods will prompt the user to re-authorize the resource usage by providing
        credentials. If user login cookies are present from previous authorization, the webview will be
        displayed and automatically dismiss itself without asking the user to re-enter credentials.
        acquireTokenSilentWithResource methods will not show UI in this case, but fail with error code
        AD_ERROR_USER_INPUT_NEEDED.
     */
    AD_PROMPT_AUTO,
    
    /*!
        The user will be prompted explicitly for credentials, consent or any other prompts, except when the
        user has Azure Authenticator installed. This option is useful in multi-user scenarios. Example is
        authenticating for the same e-mail service with different user.
     */
    AD_PROMPT_ALWAYS,
    
    /*!
        Re-authorizes (through displaying webview) the resource usage, making sure that the resulting access
        token contains updated claims. If user logon cookies are available, the user will not be asked for
        credentials again and the logon dialog will dismiss automatically. This is equivalent to passing
        prompt=refresh_session as an extra query parameter during the authorization.
     */
    AD_PROMPT_REFRESH_SESSION,
    
    /*!
        If Azure Authenticator is installed forces it to prompt the user, otherwise has the same behavior as
        AD_PROMPT_ALWAYS.
     */
    AD_FORCE_PROMPT,
} ADPromptBehavior;

/*!
 Controls where would the credentials dialog reside
 */
typedef enum
{
    /*!
     The SDK determines automatically the most suitable option, optimized for user experience.
     E.g. it may invoke another application for a single sign on, if such application is present.
     This is the default option.
     */
    AD_CREDENTIALS_AUTO,
    
    /*!
     The SDK will present an embedded dialog within the application. It will not invoke external
     application or browser.
     */
    AD_CREDENTIALS_EMBEDDED,
    
} ADCredentialsType;

@class ADAuthenticationResult;
@class MSIDLegacyTokenCacheAccessor;

/*!
    @class ADAuthenticationContext
 
    The central class for managing multiple tokens.
 
    Usage: create one per AAD or ADFS authority. As authority is required, the class cannot be
    used with "new" or the parameterless "init" selectors. Attempt to call
    [ADAuthenticationContext new] or [[ADAuthenticationContext alloc] init] will throw an exception.
 */
@interface ADAuthenticationContext : NSObject
{
    MSIDLegacyTokenCacheAccessor *_tokenCache;
    NSString* _authority;
    BOOL _validateAuthority;
    ADCredentialsType _credentialsType;
    BOOL _extendedLifetimeEnabled;
    NSString* _logComponent;
    NSUUID* _correlationId;
#if __has_feature(objc_arc)
    __weak WebViewType* _webView;
#else 
    WebViewType* _webView;
#endif
}

#if TARGET_OS_IPHONE
/*!
    Initializes an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param validateAuthority    Specifies if the authority should be validated.
    @param sharedGroup          The keychain sharing group to use for the ADAL token cache (iOS Only)
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
- (nullable id)initWithAuthority:(nonnull NSString *)authority
               validateAuthority:(BOOL)validateAuthority
                     sharedGroup:(nullable NSString *)sharedGroup
                           error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;
#endif

#if !TARGET_OS_IPHONE
/*!
    Initializes an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param validateAuthority    Specifies if the authority should be validated.
    @param delegate             An object conforming to the ADTokenCacheDelegate protocol, this is mandatory
                                if you wish to persist tokens on OS X.
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
- (nullable id)initWithAuthority:(nonnull NSString *)authority
               validateAuthority:(BOOL)validateAuthority
                   cacheDelegate:(nullable id<ADTokenCacheDelegate>)delegate
                           error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;
#endif

/*!
    Initializes an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param validateAuthority    Specifies if the authority should be validated.
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
- (nullable id)initWithAuthority:(nonnull NSString *)authority
               validateAuthority:(BOOL)validateAuthority
                           error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;


/*!
    Creates an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
+ (nullable ADAuthenticationContext*)authenticationContextWithAuthority:(nonnull NSString*)authority
                                                                  error:(ADAuthenticationError* __autoreleasing _Nullable * _Nullable)error;

/*!
    Creates an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param validate             Specifies if the authority should be validated.
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
+ (nullable ADAuthenticationContext*)authenticationContextWithAuthority:(nonnull NSString*)authority
                                                      validateAuthority:(BOOL)validate
                                                                  error:(ADAuthenticationError* __autoreleasing _Nullable * _Nullable)error;

#if TARGET_OS_IPHONE
/*!
    Creates an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param sharedGroup          The keychain sharing group to use for the ADAL token cache (iOS Only)
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
+ (nullable ADAuthenticationContext*)authenticationContextWithAuthority:(nonnull NSString*)authority
                                                            sharedGroup:(nullable NSString*)sharedGroup
                                                                  error:(ADAuthenticationError* __autoreleasing _Nullable * _Nullable)error;

/*!
    Creates an instance of ADAuthenticationContext with the provided parameters.
 
    @param authority            The AAD or ADFS authority. Example: @"https://login.microsoftonline.com/contoso.com"
    @param validate             Specifies if the authority should be validated.
    @param sharedGroup          The keychain sharing group to use for the ADAL token cache (iOS Only)
    @param error                (Optional) Any extra error details, if the method fails
 
    @return An instance of ADAuthenticationContext, nil if it fails.
 */
+ (nullable ADAuthenticationContext*)authenticationContextWithAuthority:(nonnull NSString*)authority
                                                      validateAuthority:(BOOL)validate
                                                            sharedGroup:(nullable NSString*)sharedGroup
                                                                  error:(ADAuthenticationError* __autoreleasing _Nullable * _Nullable)error;

/*!
 Ask ADAL to handle URL response. You MUST implement this API in following cases:
 1. Your application is using brokered authentication (ADCredentialsType is set to AD_CREDENTIALS_AUTO and you have configured your application to use broker), AND
 2. You're using iOS 13 multiple window feature and your code implements UISceneDelegate instead of UIApplicationDelegate
 
 You should call this API from your UISceneDelegate implementation, for example:
 
 - (void)scene:(UIScene *)scene openURLContexts:(NSSet<UIOpenURLContext *> *)URLContexts
 {
     UIOpenURLContext *context = URLContexts.anyObject;
     NSURL *url = context.URL;
     NSString *sourceApplication = context.options.sourceApplication;
     
     [ADAuthenticationContext handleADALResponse:url sourceApplication:sourceApplication];
 }
 
 Calling this API ensures that ADAL can receive tokens from the Microsoft Authenticator application.
 @return    YES if it is ADAL response and it was handled
            NO if it is not ADAL response or there was a failure in handling.
 */
+ (BOOL)handleADALResponse:(nonnull NSURL *)response sourceApplication:(nullable NSString *)sourceApplication;

#endif

/*! Represents the authority used by the context. */
@property (readonly, nonnull) NSString* authority;

/*! Controls authority validation in acquire token calls. */
@property BOOL validateAuthority;

/*! Unique identifier passed to the server and returned back with errors. Useful during investigations to correlate the
 requests and the responses from the server. If nil, a new UUID is generated on every request. */
@property (strong, nullable) NSUUID* correlationId;

/*! The credential behavior for the authentication context. See the ADCredentialsType enumeration
    definition for details */
@property ADCredentialsType credentialsType;

/*! The name of the component using this authentication context. Used in some logging and telemetry
    for clarification purposes. */
@property (retain, nullable) NSString* logComponent;

#if TARGET_OS_IPHONE
/*! The parent view controller for the authentication view controller UI. This property will be used only if
 a custom web view is NOT specified. */
@property (weak, nullable) UIViewController* parentController;
#endif

/*! Gets or sets the webview, which will be used for the credentials. If nil, the library will create a webview object
 when needed, leveraging the parentController property. */
@property (weak, nullable) WebViewType* webView;

/*! Enable to return access token with extended lifetime during server outage. */
@property BOOL extendedLifetimeEnabled;

/*!
    List of additional ESTS features that client handles.
 */
@property (strong, nullable) NSArray<NSString *> *clientCapabilities;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. If neither of these attempts succeeds, the method will use the provided assertion to get an 
 access token from the service.
 
 @param assertion The assertion representing the authenticated user.
 @param assertionType The assertion type of the user assertion.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param userId The required user id of the authenticated user.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenForAssertion:(nonnull NSString*)assertion
                   assertionType:(ADAssertionType)assertionType
                        resource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                          userId:(nullable NSString*)userId
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;


/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
 credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
 leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
 UI displaying is desired.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                     redirectUri:(nonnull NSURL*)redirectUri
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
 credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
 leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
 UI displaying is desired.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user to be prepopulated in the credentials form. Additionally, if token is found in the cache,
 it may not be used if it belongs to different token. This parameter can be nil.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                     redirectUri:(nonnull NSURL*)redirectUri
                          userId:(nonnull NSString*)userId
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. If neither of these attempts succeeds, the method will display
 credentials web UI for the user to re-authorize the resource usage. Logon cookie from previous authorization may be
 leveraged by the web UI, so user may not be actuall prompted. Use the other overloads if a more precise control of the
 UI displaying is desired.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user to be prepopulated in the credentials form. Additionally, if token is found in the cache,
 it may not be used if it belongs to different token. This parameter can be nil.
 @param queryParams The extra query parameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                     redirectUri:(nonnull NSURL*)redirectUri
                          userId:(nullable NSString*)userId
            extraQueryParameters:(nullable NSString*)queryParams
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The behavior is controlled by the promptBehavior parameter on whether to re-authorize the
 resource usage (through webview credentials UI) or attempt to use the cached tokens first.
 @param resource The resource for whom token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param promptBehavior Controls if any credentials UI will be shown
 @param userId The user to be prepopulated in the credentials form. Additionally, if token is found in the cache,
 it may not be used if it belongs to different token. This parameter can be nil.
 @param queryParams The extra query parameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                     redirectUri:(nonnull NSURL*)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                          userId:(nullable NSString*)userId
            extraQueryParameters:(nullable NSString*)queryParams
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The behavior is controlled by the promptBehavior parameter on whether to re-authorize the
 resource usage (through webview credentials UI) or attempt to use the cached tokens first.
 @param resource The resource for whom token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param promptBehavior Controls if any credentials UI will be shown.
 @param userId An ADUserIdentifier object describing the user being authenticated
 @param queryParams The extra query parameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
 @param completionBlock the block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString*)resource
                        clientId:(nonnull NSString*)clientId
                     redirectUri:(nonnull NSURL*)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                  userIdentifier:(nullable ADUserIdentifier*)userId
            extraQueryParameters:(nullable NSString*)queryParams
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function accepts claims challenge returned from middle tier service, which will be sent to authorization endpoint. If claims parameter is not nil/empty and prompt behavior is AD_PROMPT_AUTO, cached access token will be skipped and the refresh token will be used. ADAL will show the credentials UI if necessary.
 @param resource The resource for whom token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param promptBehavior Controls if any credentials UI will be shown.
 @param userId An ADUserIdentifier object describing the user being authenticated
 @param queryParams The extra query parameters will be appended to the HTTP request to the authorization endpoint. This parameter can be nil.
 @param claims The claims parameter that needs to be sent to authorization endpoint. It should be URL-encoded.
 @param completionBlock the block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithResource:(nonnull NSString *)resource
                        clientId:(nonnull NSString *)clientId
                     redirectUri:(nonnull NSURL *)redirectUri
                  promptBehavior:(ADPromptBehavior)promptBehavior
                  userIdentifier:(nullable ADUserIdentifier *)userId
            extraQueryParameters:(nullable NSString *)queryParams
                          claims:(nullable NSString *)claims
                 completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
 If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.
 @param resource the resource whose token is needed.
 @param clientId the client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithResource:(nonnull NSString*)resource
                              clientId:(nonnull NSString*)clientId
                           redirectUri:(nonnull NSURL*)redirectUri
                       completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. Additionally, if no suitable access token is found in the cache, but refresh token is available,
 the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
 If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user to be prepopulated in the credentials form. Additionally, if token is found in the cache,
 it may not be used if it belongs to different token. This parameter can be nil.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithResource:(nonnull NSString*)resource
                              clientId:(nonnull NSString*)clientId
                           redirectUri:(nonnull NSURL*)redirectUri
                                userId:(nonnull NSString*)userId
                       completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will first look at the cache and automatically check for token
 expiration. If forceRefresh flag is passed in as YES, access token in cache will be skipped.
 If no suitable access token is found in the cache or forceRefresh flag is YES, but refresh token is available,
 the function will use the refresh token automatically. This method will not show UI for the user to reauthorize resource usage.
 If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user to be used to look up the access token and refresh token in cache
 @param forceRefresh The flag to skip existing access token in cache.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithResource:(nonnull NSString *)resource
                              clientId:(nonnull NSString *)clientId
                           redirectUri:(nonnull NSURL *)redirectUri
                                userId:(nullable NSString *)userId
                          forceRefresh:(BOOL)forceRefresh
                       completionBlock:(nonnull ADAuthenticationCallback)completionBlock;


/*! Follows the OAuth2 protocol (RFC 6749). The function accepts claims challenge returned from middle tier service, which will be sent to token endpoint. If claims parameter is not nil/empty, access tokens in cache will be skipped and refresh token will be tried.
 If reauthorization is needed, the method will return an error with code AD_ERROR_USER_INPUT_NEEDED.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user to be used to look up the access token and refresh token in cache
 @param claims The claims parameter that needs to be sent to the token endpoint. It should be URL-encoded.
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenSilentWithResource:(nonnull NSString *)resource
                              clientId:(nonnull NSString *)clientId
                           redirectUri:(nonnull NSURL *)redirectUri
                                userId:(nullable NSString *)userId
                                claims:(nullable NSString *)claims
                       completionBlock:(nonnull ADAuthenticationCallback)completionBlock;


/*! Follows the OAuth2 protocol (RFC 6749). The function will use the refresh token provided to get access token.
 This method will not show UI for the user to reauthorize resource usage.
 If the call fails, error will be included in the result.
 @param refreshToken The refresh token provided in order to get acces token.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithRefreshToken:(nonnull NSString *)refreshToken
                            resource:(nonnull NSString *)resource
                            clientId:(nonnull NSString *)clientId
                         redirectUri:(nonnull NSURL *)redirectUri
                     completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

/*! Follows the OAuth2 protocol (RFC 6749). The function will use the refresh token provided to get access token.
 This method will not show UI for the user to reauthorize resource usage.
 If the call fails, error will be included in the result.
 @param refreshToken The refresh token provided in order to get acces token.
 @param resource The resource whose token is needed.
 @param clientId The client identifier
 @param redirectUri The redirect URI according to OAuth2 protocol
 @param userId The user matching the refresh token provided. If there is a mismatch, error will be returned
 @param completionBlock The block to execute upon completion. You can use embedded block, e.g. "^(ADAuthenticationResult res){ <your logic here> }"
 */
- (void)acquireTokenWithRefreshToken:(nonnull NSString *)refreshToken
                            resource:(nonnull NSString *)resource
                            clientId:(nonnull NSString *)clientId
                         redirectUri:(nonnull NSURL *)redirectUri
                              userId:(nonnull NSString *)userId
                     completionBlock:(nonnull ADAuthenticationCallback)completionBlock;

@end










