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

//A wrapper around checkAndHandleBadArgument. Assumes that "completionMethod" is in scope:
#define HANDLE_ARGUMENT(ARG, CORRELATION_ID) \
    if (![ADAuthenticationContext checkAndHandleBadArgument:ARG \
                                               argumentName:TO_NSSTRING(#ARG) \
                                              correlationId:CORRELATION_ID \
                                            completionBlock:completionBlock]) \
    { \
    return; \
    }

#define CHECK_FOR_NIL(_val) \
    if (!_val) { completionBlock([ADAuthenticationResult resultFromError:[ADAuthenticationError unexpectedInternalError:@"" #_val " is nil!" correlationId:[_requestParams correlationId]]]); return; }

#import "ADAL_Internal.h"

@class ADUserIdentifier;
@class ADTokenCacheAccessor;
@protocol ADTokenCacheDataSource;

#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult+Internal.h"
#import "ADOAuth2Constants.h"
#import "ADTokenCacheAccessor.h"

extern NSString* const ADUnknownError;
extern NSString* const ADCredentialsNeeded;
extern NSString* const ADInteractionNotSupportedInExtension;
extern NSString* const ADServerError;
extern NSString* const ADRedirectUriInvalidError;

@interface ADAuthenticationContext (Internal)

+ (BOOL)checkAndHandleBadArgument:(NSObject *)argumentValue
                     argumentName:(NSString *)argumentName
                    correlationId:(NSUUID *)correlationId
                  completionBlock:(ADAuthenticationCallback)completionBlock;

+ (BOOL)handleNilOrEmptyAsResult:(NSObject *)argumentValue
                    argumentName:(NSString *)argumentName
            authenticationResult:(ADAuthenticationResult **)authenticationResult;

+ (ADAuthenticationError*)errorFromDictionary:(NSDictionary *)dictionary
                                    errorCode:(ADErrorCode)errorCode;


- (id)initWithAuthority:(NSString *)authority
      validateAuthority:(BOOL)validateAuthority
             tokenCache:(id<ADTokenCacheDataSource>)tokenCache
                  error:(ADAuthenticationError *__autoreleasing *)error;

+ (BOOL)isFinalResult:(ADAuthenticationResult *)result;

+ (NSString*)getPromptParameter:(ADPromptBehavior)prompt;

+ (BOOL)isForcedAuthorization:(ADPromptBehavior)prompt;

+ (ADAuthenticationResult*)updateResult:(ADAuthenticationResult *)result
                                 toUser:(ADUserIdentifier *)userId;

- (BOOL)hasCacheStore;

+ (BOOL)canHandleResponse:(NSURL *)response
        sourceApplication:(NSString *)sourceApplication;

@end

@interface ADAuthenticationContext (CacheStorage)

- (void)setTokenCacheStore:(id<ADTokenCacheDataSource>)tokenCacheStore;
- (ADTokenCacheAccessor *)tokenCacheStore;

@end
