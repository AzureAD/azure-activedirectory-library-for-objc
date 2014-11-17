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
#import <ADALiOS/ADAuthenticationContext.h>
#import "ADBrokerContext.h"
#import "ADAuthenticationBroker.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADConstants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADBrokerKeychainTokenCacheStore.h"

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

+ (void) invokeBroker: (NSString*) requestPayload
sourceApplication: (NSString*) sourceApplication
completionBlock: (ADAuthenticationCallback) completionBlock
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
    HANDLE_ARGUMENT([queryParamsMap valueForKey:BROKER_KEY]);
    
    ADAuthenticationError* error = nil;
    ADAuthenticationContext* ctx = [[ADAuthenticationContext alloc] initWithAuthority:[queryParamsMap valueForKey:AUTHORITY] validateAuthority:NO tokenCacheStore:[ADBrokerKeychainTokenCacheStore new] error:&error];
    if(!ctx || error)
    {
        
    } else{
        
    }
    
    
}

@end