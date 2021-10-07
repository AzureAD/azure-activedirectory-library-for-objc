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

#import "ADALAuthenticationContext+Internal.h"
#import "ADALUserIdentifier.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALHelpers.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "NSDictionary+MSIDExtensions.h"
#if TARGET_OS_IPHONE
#import "ADALBrokerNotificationManager.h"
#endif

NSString* const ADUnknownError = @"Uknown error.";
NSString* const ADCredentialsNeeded = @"The user credentials are needed to obtain access token. Please call the non-silent acquireTokenWithResource methods.";
NSString* const ADInteractionNotSupportedInExtension = @"Interaction is not supported in an app extension.";
NSString* const ADServerError = @"The authentication server returned an error: %@.";
NSString* const ADRedirectUriInvalidError = @"Your AuthenticationContext is configured to allow brokered authentication but your redirect URI is not setup properly. Make sure your redirect URI is in the form of <app-scheme>://<bundle-id> (e.g. \"x-msauth-testapp://com.microsoft.adal.testapp\") and that the \"app-scheme\" you choose is registered in your application's info.plist.";

@implementation ADALAuthenticationContext (Internal)

+ (BOOL)handleNilOrEmptyAsResult:(NSObject*)argumentValue
                    argumentName:(NSString*)argumentName
            authenticationResult:(ADALAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString msidIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADALAuthenticationError* argumentError = [ADALAuthenticationError errorFromArgument:argumentValue argumentName:argumentName correlationId:nil];
        *authenticationResult = [ADALAuthenticationResult resultFromError:argumentError];
        return NO;
    }
    
    return YES;
}
//Obtains a protocol error from the response:
+ (ADALAuthenticationError*)errorFromDictionary:(NSDictionary*)dictionary
                                    errorCode:(ADALErrorCode)errorCode
{
    //First check for explicit OAuth2 protocol error:
    NSString *serverOAuth2Error = [dictionary msidStringObjectForKey:MSID_OAUTH2_ERROR];
    if (serverOAuth2Error)
    {
        NSString *responseCorrelationId = [dictionary msidStringObjectForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE];
        NSUUID *correlationId = responseCorrelationId ? [[NSUUID alloc] initWithUUIDString:responseCorrelationId] : nil;

        ADALErrorCode code = errorCode;
        NSString *suberror = [dictionary msidStringObjectForKey:ADAL_AUTH_SUBERROR];
        NSMutableDictionary *userInfo = [NSMutableDictionary new];
        userInfo[ADSuberrorKey] = suberror;

        if (suberror && [suberror isEqualToString:ADAL_AUTH_PROTECTION_POLICY_REQUIRED])
        {
            code = AD_ERROR_SERVER_PROTECTION_POLICY_REQUIRED;
        }

        userInfo[ADUserIdKey] = [dictionary msidStringObjectForKey:ADAL_AUTH_ADDITIONAL_USER_IDENTIFIER];
        NSString *errorDescription = [dictionary msidStringObjectForKey:MSID_OAUTH2_ERROR_DESCRIPTION];

        return [ADALAuthenticationError OAuthServerError:serverOAuth2Error
                                           description:errorDescription
                                                  code:code
                                         correlationId:correlationId
                                              userInfo:userInfo];
    }
    
    return nil;
}

//Returns YES if we shouldn't attempt other means to get access token.
//
+ (BOOL)isFinalResult:(ADALAuthenticationResult*)result
{
    if (!result)
    {
        return NO;
    }
    
    // Successful results are final results!
    if (result.status == AD_SUCCEEDED)
    {
        return YES;
    }
    
    // Protocol Code is used for OAuth errors (and should only be used for OAuth errors...). If we
    // received an OAuth error that means that the server is up and responsive, just that something
    // about the token was bad.
    if (result.error && !result.error.protocolCode)
    {
        return YES;
    }
    
    return NO;
}

//Translates the ADPromptBehavior into prompt query parameter. May return nil, if such
//parameter is not needed.
+ (NSString*)getPromptParameter:(ADPromptBehavior)prompt
{
    switch (prompt) {
        case AD_PROMPT_ALWAYS:
        case AD_FORCE_PROMPT:
            return @"login";
        case AD_PROMPT_REFRESH_SESSION:
            return @"refresh_session";
        default:
            return nil;
    }
}

+ (BOOL)isForcedAuthorization:(ADPromptBehavior)prompt
{
    //If prompt parameter needs to be passed, re-authorization is needed.
    return [ADALAuthenticationContext getPromptParameter:prompt] != nil;
}

//Used in the flows, where developer requested an explicit user. The method compares
//the user for the obtained tokens (if provided by the server). If the user is different,
//an error result is returned. Returns the same result, if no issues are found.
+ (ADALAuthenticationResult*)updateResult:(ADALAuthenticationResult*)result
                                 toUser:(ADALUserIdentifier*)userId
                           verifyUserId:(BOOL)verifyUserId
{
    if (!result)
    {
        ADALAuthenticationError* error =
        [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"ADALAuthenticationResult is nil"
                                              correlationId:nil];
        return [ADALAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    if (AD_SUCCEEDED != result.status || !userId || [NSString msidIsStringNilOrBlank:userId.userId] || userId.type == OptionalDisplayableId)
    {
        //No user to compare - either no specific user id requested, or no specific userId obtained:
        return result;
    }
    
    ADALUserInformation* userInfo = [[result tokenCacheItem] userInformation];
    
    if (!userInfo || ![userId userIdMatchString:userInfo])
    {
        // TODO: This behavior is questionable. Look into removing.
        return result;
    }
    
    if (verifyUserId &&
        (![ADALUserIdentifier identifier:userId matchesInfo:userInfo]))
    {
        ADALAuthenticationError* error =
        [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_WRONG_USER
                                               protocolCode:nil
                                               errorDetails:@"Different user was returned by the server then specified in the acquireToken call. If this is a new sign in use and ADALUserIdentifier is of OptionalDisplayableId type, pass in the userId returned on the initial authentication flow in all future acquireToken calls."
                                              correlationId:nil];
        return [ADALAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    return result;
}

static MSIDAADV1Oauth2Factory *s_oauthFactory;

- (MSIDOauth2Factory *)oauthFactory
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_oauthFactory = [MSIDAADV1Oauth2Factory new];
    });
    
    return s_oauthFactory;
}


+ (BOOL)canHandleResponse:(NSURL *)response
        sourceApplication:(NSString *)sourceApplication
{
#if TARGET_OS_IPHONE
    // sourceApplication could be nil, we want to return early if we know for sure response is not from broker
    BOOL responseNotFromBroker = sourceApplication && ![self isResponseFromBroker:sourceApplication response:response];
    if (responseNotFromBroker) { return NO; }
    
    NSURLComponents *components = [NSURLComponents componentsWithURL:response resolvingAgainstBaseURL:NO];
    NSString *qp = [components percentEncodedQuery];
    NSDictionary* queryParamsMap = [NSDictionary msidDictionaryFromWWWFormURLEncodedString:qp];
    
    NSString *protocolVersion = queryParamsMap[ADAL_BROKER_MESSAGE_VERSION];
    BOOL isValidVersion = [protocolVersion isEqualToString:@"2"];
    
    NSDictionary *resumeDictionary = [[NSUserDefaults standardUserDefaults] objectForKey:kAdalResumeDictionaryKey];
    
    if (!resumeDictionary) MSID_LOG_INFO(nil, @"No resume dictionary found.");
    
    NSString *redirectUri = [resumeDictionary objectForKey:@"redirect_uri"];
    if (redirectUri && ![response.absoluteString.lowercaseString hasPrefix:redirectUri.lowercaseString])
    {
        return NO;
    }
    
    BOOL isADALInitiatedRequest = [resumeDictionary[kAdalSDKNameKey] isEqualToString:kAdalSDKObjc] || [[ADALBrokerNotificationManager sharedInstance] hasCallback];
    
    return isValidVersion && isADALInitiatedRequest;
#else
    (void)response;
    (void)sourceApplication;
    return NO;
#endif
}

+ (BOOL)isResponseFromBroker:(NSString *)sourceApplication
                    response:(NSURL *)response
{
    BOOL isBroker = [sourceApplication isEqualToString:ADAL_BROKER_APP_BUNDLE_ID]
                    || [sourceApplication isEqualToString:ADAL_BROKER_APP_BUNDLE_ID_DOGFOOD];
    
    return response && isBroker;
}

+ (BOOL)handleBrokerResponse:(NSURL*)response sourceApplication:(nullable NSString *)sourceApplication;
{
    return [ADALAuthenticationRequest internalHandleBrokerResponse:response sourceApplication:sourceApplication];
}

@end
