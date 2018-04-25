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

#import "ADAuthenticationContext+Internal.h"
#import "ADUserIdentifier.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADHelpers.h"

NSString* const ADUnknownError = @"Uknown error.";
NSString* const ADCredentialsNeeded = @"The user credentials are needed to obtain access token. Please call the non-silent acquireTokenWithResource methods.";
NSString* const ADInteractionNotSupportedInExtension = @"Interaction is not supported in an app extension.";
NSString* const ADServerError = @"The authentication server returned an error: %@.";
NSString* const ADRedirectUriInvalidError = @"Your AuthenticationContext is configured to allow brokered authentication but your redirect URI is not setup properly. Make sure your redirect URI is in the form of <app-scheme>://<bundle-id> (e.g. \"x-msauth-testapp://com.microsoft.adal.testapp\") and that the \"app-scheme\" you choose is registered in your application's info.plist.";

@implementation ADAuthenticationContext (Internal)

+ (BOOL)handleNilOrEmptyAsResult:(NSObject*)argumentValue
                    argumentName:(NSString*)argumentName
            authenticationResult:(ADAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString msidIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName correlationId:nil];
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
    NSString* serverOAuth2Error = [dictionary objectForKey:MSID_OAUTH2_ERROR];
    if (![NSString msidIsStringNilOrBlank:serverOAuth2Error])
    {
        NSString* errorDetails = [dictionary objectForKey:MSID_OAUTH2_ERROR_DESCRIPTION];
        // Error response from the server
        NSUUID* correlationId = [dictionary objectForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE] ?
                                [[NSUUID alloc] initWithUUIDString:[dictionary objectForKey:MSID_OAUTH2_CORRELATION_ID_RESPONSE]]:
                                nil;
        return [ADAuthenticationError OAuthServerError:serverOAuth2Error description:errorDetails code:errorCode correlationId:correlationId];
    }
    
    return nil;
}

//Returns YES if we shouldn't attempt other means to get access token.
//
+ (BOOL)isFinalResult:(ADAuthenticationResult*)result
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
    return [ADAuthenticationContext getPromptParameter:prompt] != nil;
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
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                               protocolCode:nil
                                               errorDetails:@"ADAuthenticationResult is nil"
                                              correlationId:nil];
        return [ADAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    if (AD_SUCCEEDED != result.status || !userId || [NSString msidIsStringNilOrBlank:userId.userId] || userId.type == OptionalDisplayableId)
    {
        //No user to compare - either no specific user id requested, or no specific userId obtained:
        return result;
    }
    
    ADUserInformation* userInfo = [[result tokenCacheItem] userInformation];
    
    if (!userInfo || ![userId userIdMatchString:userInfo])
    {
        // TODO: This behavior is questionable. Look into removing.
        return result;
    }
    
    if (![ADUserIdentifier identifier:userId matchesInfo:userInfo])
    {
        ADAuthenticationError* error =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_WRONG_USER
                                               protocolCode:nil
                                               errorDetails:@"Different user was returned by the server then specified in the acquireToken call. If this is a new sign in use and ADUserIdentifier is of OptionalDisplayableId type, pass in the userId returned on the initial authentication flow in all future acquireToken calls."
                                              correlationId:nil];
        return [ADAuthenticationResult resultFromError:error correlationId:[result correlationId]];
    }
    
    return result;
}

@end
