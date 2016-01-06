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

#import "ADAuthenticationContext+Internal.h"
#import "ADUserIdentifier.h"

NSString* const ADUnknownError = @"Uknown error.";
NSString* const ADCredentialsNeeded = @"The user credentials are need to obtain access token. Please call the non-silent acquireTokenWithResource methods.";
NSString* const ADServerError = @"The authentication server returned an error: %@.";
NSString* const ADBrokerAppIdentifier = @"com.microsoft.azureadauthenticator";
NSString* const ADRedirectUriInvalidError = @"Redirect URI cannot be used to invoke the application. Update your redirect URI to be of  <app-scheme>://<bundle-id> format";

@implementation ADAuthenticationContext (Internal)

/*! Verifies that the string parameter is not nil or empty. If it is,
 the method generates an error and set it to an authentication result.
 Then the method calls the callback with the result.
 The method returns if the argument is valid. If the method returns false,
 the calling method should return. */
+ (BOOL)checkAndHandleBadArgument:(NSObject*)argumentValue
                     argumentName:(NSString*)argumentName
                  completionBlock:(ADAuthenticationCallback)completionBlock
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName];
        ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:argumentError];
        completionBlock(result);//Call the callback to tell about the result
        return NO;
    }
    else
    {
        return YES;
    }
}

+ (BOOL)handleNilOrEmptyAsResult:(NSObject*)argumentValue
                    argumentName:(NSString*)argumentName
            authenticationResult:(ADAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName];
        *authenticationResult = [ADAuthenticationResult resultFromError:argumentError];
        return NO;
    }
    
    return YES;
}
//Obtains a protocol error from the response:
+ (ADAuthenticationError*)errorFromDictionary:(NSDictionary*)dictionary
                                    errorCode:(ADErrorCode)errorCode
{
    //First check for explicit OAuth2 protocol error:
    NSString* serverOAuth2Error = [dictionary objectForKey:OAUTH2_ERROR];
    if (![NSString adIsStringNilOrBlank:serverOAuth2Error])
    {
        NSString* errorDetails = [dictionary objectForKey:OAUTH2_ERROR_DESCRIPTION];
        // Error response from the server
        return [ADAuthenticationError errorFromAuthenticationError:errorCode
                                                      protocolCode:serverOAuth2Error
                                                      errorDetails:(errorDetails) ? errorDetails : [NSString stringWithFormat:ADServerError, serverOAuth2Error]];
    }
    //In the case of more generic error, e.g. server unavailable, DNS error or no internet connection, the error object will be directly placed in the dictionary:
    return [dictionary objectForKey:AUTH_NON_PROTOCOL_ERROR];
}

//Returns YES if we shouldn't attempt other means to get access token.
//
+ (BOOL)isFinalResult:(ADAuthenticationResult*)result
{
    return (AD_SUCCEEDED == result.status) /* access token provided, no need to try anything else */
    || (result.error && !result.error.protocolCode); //Connection is down, server is unreachable or DNS error. No need to try refresh tokens.
}

//Return YES if the failure is because of server error.
//500 errors are the only ones that we explicitly retry
+ (BOOL)isServerError:(ADAuthenticationResult*)result
{
    return [result status]==AD_FAILED && [[[result error] protocolCode] isEqualToString:@"500"];
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
    return [ADAuthenticationContext getPromptParameter:prompt] != nil;
}

- (BOOL)hasCacheStore
{
    return self.tokenCacheStore != nil;
}

//Used in the flows, where developer requested an explicit user. The method compares
//the user for the obtained tokens (if provided by the server). If the user is different,
//an error result is returned. Returns the same result, if no issues are found.
+ (ADAuthenticationResult*)updateResult:(ADAuthenticationResult*)result
                                 toUser:(ADUserIdentifier*)userId
{
    if (!result)
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"ADAuthenticationResult is nil"];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    if (AD_SUCCEEDED != result.status || !userId || [NSString adIsStringNilOrBlank:userId.userId] || userId.type == OptionalDisplayableId)
    {
        //No user to compare - either no specific user id requested, or no specific userId obtained:
        return result;
    }
    
    ADUserInformation* userInfo = [[result tokenCacheStoreItem] userInformation];
    
    if (!userInfo || ![userId userIdMatchString:userInfo])
    {
        // TODO: This behavior is questionable. Look into removing.
        return result;
    }
    
    if (![ADUserIdentifier identifier:userId matchesInfo:userInfo])
    {
        NSString* errorText = [NSString stringWithFormat:@"Different user was authenticated. Expected: '%@'; Actual: '%@'. Either the user entered credentials for different user, or cookie for different logged user is present. Consider calling acquireToken with AD_PROMPT_ALWAYS to ignore the cookie.",
                               userId.userId, [userId userIdMatchString:userInfo]];
        
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_WRONG_USER
                                               protocolCode:nil
                                               errorDetails:errorText];
        return [ADAuthenticationResult resultFromError:error];
    }
    
    return result;
}

@end
