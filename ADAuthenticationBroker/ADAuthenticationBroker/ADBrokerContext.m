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

#import <Foundation/Foundation.h>
#import <ADALiOS/ADAuthenticationSettings.h>
#import "ADBrokerContext.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADConstants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADBrokerKeychainTokenCacheStore.h"
#import "ADBrokerHelpers.h"

@implementation ADBrokerContext

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG) \
if (![self checkAndHandleBadArgument:ARG \
argumentName:TO_NSSTRING(#ARG) \
completionBlock:completionBlock]) \
{ \
return; \
}

+ (BOOL) handleNilOrEmptyAsResult:(NSObject*) argumentValue
                     argumentName: (NSString*) argumentName
             authenticationResult: (ADAuthenticationResult**)authenticationResult
{
    if (!argumentValue || ([argumentValue isKindOfClass:[NSString class]] && [NSString adIsStringNilOrBlank:(NSString*)argumentValue]))
    {
        ADAuthenticationError* argumentError = [ADAuthenticationError errorFromArgument:argumentValue argumentName:argumentName];
        *authenticationResult = [ADAuthenticationResult resultFromError:argumentError];
        return NO;
    }
    
    return YES;
}

/*! Verifies that the string parameter is not nil or empty. If it is,
 the method generates an error and set it to an authentication result.
 Then the method calls the callback with the result.
 The method returns if the argument is valid. If the method returns false,
 the calling method should return. */
+(BOOL) checkAndHandleBadArgument: (NSObject*) argumentValue
                     argumentName: (NSString*) argumentName
                  completionBlock: (ADAuthenticationCallback)completionBlock
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

+ (void) invokeBrokerLocally: (NSString*) requestPayload
             completionBlock: (ADBrokerCallback) completionBlock
{
    [ADBrokerContext invokeBrokerForSourceApplication:requestPayload sourceApplication:LOCAL_APPLICATION completionBlock:completionBlock];
}


+ (void) invokeBrokerForSourceApplication: (NSString*) requestPayload
                        sourceApplication: (NSString*) sourceApplication
                          completionBlock: (ADBrokerCallback) completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    HANDLE_ARGUMENT(requestPayload);
    HANDLE_ARGUMENT(sourceApplication);
    
    NSArray * parts = [requestPayload componentsSeparatedByString:@"?"];
    NSString *qp = [parts objectAtIndex:1];
    NSDictionary* queryParamsMap = [NSDictionary adURLFormDecode:qp];
    
    HANDLE_ARGUMENT([queryParamsMap valueForKey:AUTHORITY]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:CLIENT_ID]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:CORRELATION_ID]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:REDIRECT_URI]);
    HANDLE_ARGUMENT([queryParamsMap valueForKey:BROKER_KEY]);
    
    //validate source application against redirect uri
    ADAuthenticationError* error = nil;
    NSURL *redirectUri = [[NSURL alloc] initWithString:[queryParamsMap valueForKey:REDIRECT_URI]];
    if(![NSString adSame:sourceApplication toString:[redirectUri host]]){
        //TODO - get right error
        error = [ADAuthenticationError errorFromNSError:nil errorDetails:@"source application bundle identifier should be same as the redirect URI domain"];
    }
    
    if(!error)
    {
        [ADAuthenticationSettings sharedInstance].credentialsType = AD_CREDENTIALS_EMBEDDED;
        ADAuthenticationContext* ctx = [[ADAuthenticationContext alloc] initWithAuthority:[queryParamsMap valueForKey:AUTHORITY]
                                                                        validateAuthority:NO
                                                                          tokenCacheStore:[[ADBrokerKeychainTokenCacheStore alloc]initWithSourceApp:sourceApplication]
                                                                                    error:&error];
        ctx.correlationId = [[NSUUID alloc] initWithUUIDString:[queryParamsMap valueForKey:CORRELATION_ID]];
        if(ctx)
        {
            
            [ctx acquireTokenWithResource:[queryParamsMap valueForKey:RESOURCE]
                                 clientId:[queryParamsMap valueForKey:CLIENT_ID]
                              redirectUri:redirectUri
                                   userId:[queryParamsMap valueForKey:USER_ID]
                     extraQueryParameters:[queryParamsMap valueForKey:EXTRA_QUERY_PARAMETERS]
                          completionBlock:^(ADAuthenticationResult *result)
             {
                 NSString* response = nil;
                 if(result.status == AD_SUCCEEDED){
                     
                     NSString* rawIdToken = @"";
                     if(result.tokenCacheStoreItem.userInformation){
                         rawIdToken = result.tokenCacheStoreItem.userInformation.rawIdToken;
                     }
                     
                     response = [NSString stringWithFormat:@"access_token=%@&id_token=%@", result.accessToken, rawIdToken];
                     response = [NSString Base64EncodeData:[ADBrokerHelpers encryptData:response key:[NSString Base64DecodeData:[queryParamsMap valueForKey:BROKER_KEY]]]];
                     response = [NSString stringWithFormat:@"response=%@", response];
                 } else{
                     response = [ADBrokerContext getErrorResponse: result.error];
                 }
                 
                 [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:REDIRECT_URI] response:response];
             }];
            return;
        }
    }
    
    if(error){
        NSString* response = [ADBrokerContext getErrorResponse: error];
        [ADBrokerContext openAppInBackground:[queryParamsMap valueForKey:REDIRECT_URI] response:response];
        return;
    }
}

+(void)openAppInBackground:(NSString *)application
                       response:(NSString *)response
{        NSURL* appUrl = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%@/broker?%@", application, response]];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] openURL:appUrl];
    });
}

+ (NSString*) getErrorResponse:(ADAuthenticationError*) error
{
    return [NSString stringWithFormat:@"code=%@&error_details=%@", error.protocolCode, error.errorDetails];
}

@end