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

#define CHECK_FOR_NIL(_val) \
    if (!_val) { completionBlock([ADALAuthenticationResult resultFromError:[ADALAuthenticationError unexpectedInternalError:@"" #_val " is nil!" correlationId:[_requestParams correlationId]]]); return; }

#import "ADAL_Internal.h"

@class ADALUserIdentifier;
@protocol ADALTokenCacheDataSource;
@class MSIDOauth2Factory;

#import "ADALAuthenticationContext.h"
#import "ADALAuthenticationResult+Internal.h"

#import "MSIDOAuth2Constants.h"

extern NSString* const ADUnknownError;
extern NSString* const ADCredentialsNeeded;
extern NSString* const ADInteractionNotSupportedInExtension;
extern NSString* const ADServerError;
extern NSString* const ADRedirectUriInvalidError;

@interface ADALAuthenticationContext (Internal)

+ (BOOL)handleNilOrEmptyAsResult:(NSObject *)argumentValue
                    argumentName:(NSString *)argumentName
            authenticationResult:(ADALAuthenticationResult **)authenticationResult;

+ (ADALAuthenticationError*)errorFromDictionary:(NSDictionary *)dictionary
                                    errorCode:(ADErrorCode)errorCode;

+ (BOOL)isFinalResult:(ADALAuthenticationResult *)result;

+ (NSString*)getPromptParameter:(ADPromptBehavior)prompt;

+ (BOOL)isForcedAuthorization:(ADPromptBehavior)prompt;


+ (ADALAuthenticationResult*)updateResult:(ADALAuthenticationResult*)result
                                 toUser:(ADALUserIdentifier*)userId
                           verifyUserId:(BOOL)verifyUserId;

@property (readonly) MSIDOauth2Factory *oauthFactory;

+ (BOOL)canHandleResponse:(NSURL *)response
        sourceApplication:(NSString *)sourceApplication;

+ (BOOL)isResponseFromBroker:(NSString*)sourceApplication
                    response:(NSURL*)response;

+ (BOOL)handleBrokerResponse:(NSURL*)response sourceApplication:(NSString *)sourceApplication;

@end

