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

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG) \
    if (![ADAuthenticationContext checkAndHandleBadArgument:ARG \
                                             argumentName:TO_NSSTRING(#ARG) \
                                          completionBlock:completionBlock]) \
    { \
    return; \
    }

#import "ADALiOS.h"

#import "ADAuthenticationContext.h"
#import "ADAuthenticationContext+AcquireToken.h"
#import "ADAuthenticationContext+AcquireAssertion.h"
#import "ADAuthenticationContext+TokenCaching.h"
#import "ADAuthenticationContext+Broker.h"
#import "ADAuthenticationContext+WebRequest.h"

#import "ADAuthenticationResult+Internal.h"
#import "ADOAuth2Constants.h"

typedef void(^ADAuthorizationCodeCallback)(NSString*, ADAuthenticationError*);


extern NSString* const ADUnknownError;
extern NSString* const ADCredentialsNeeded;
extern NSString* const ADServerError;
extern NSString* const ADBrokerAppIdentifier;
extern NSString* const ADRedirectUriInvalidError;


@interface ADAuthenticationContext (Internal)

+ (BOOL)checkAndHandleBadArgument:(NSObject*) argumentValue
                     argumentName:(NSString*) argumentName
                  completionBlock:(ADAuthenticationCallback)completionBlock;
+ (BOOL)handleNilOrEmptyAsResult:(NSObject*)argumentValue
                    argumentName:(NSString*)argumentName
            authenticationResult:(ADAuthenticationResult**)authenticationResult;
+ (ADAuthenticationError*)errorFromDictionary:(NSDictionary*)dictionary
                                    errorCode:(ADErrorCode)errorCode;


+ (BOOL)isFinalResult:(ADAuthenticationResult*)result;

+ (NSString*)getPromptParameter:(ADPromptBehavior)prompt;
+ (BOOL)isForcedAuthorization:(ADPromptBehavior)prompt;

- (ADAuthenticationResult*)updateResult:(ADAuthenticationResult*)result
                                 toUser:(NSString*) userId;

- (NSUUID*)getCorrelationId;
- (void)setCorrelationId:(NSUUID*)correlationId;

//Makes sure that the correlation id contains a valid UUID.
//Generates a new one if needed.
- (void)updateCorrelationId:(NSUUID* __autoreleasing*)correlationId;

@end
