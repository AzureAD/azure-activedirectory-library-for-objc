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

#import "ADAuthenticationError.h"
#import "ADTokenCacheItem.h"

#define AUTH_ERROR(_CODE, _DETAILS, _CORRELATION) \
    ADAuthenticationError* adError = \
    [ADAuthenticationError errorFromAuthenticationError:_CODE \
                                           protocolCode:nil \
                                           errorDetails:_DETAILS \
                                          correlationId:_CORRELATION]; \
    if (error) { *error = adError; }



#define AUTH_ERROR_RETURN_IF_NIL(_VAL, _CODE, _DETAILS, _CORRELATION) \
    if (_VAL == nil) { \
        AUTH_ERROR(_CODE, _DETAILS, _CORRELATION); \
        return nil; \
    }

#define ARG_RETURN_IF_NIL(_ARG, _CORRELATION) \
    if (_ARG == nil) { \
        AUTH_ERROR(AD_ERROR_DEVELOPER_INVALID_ARGUMENT, @#_ARG " should not be nil.", _CORRELATION); \
        return nil; \
    }



#define AUTH_ERROR_UNDERLYING(_CODE, _DETAILS, _UNDERLYING, _CORRELATION) \
    ADAuthenticationError* adError = \
    [ADAuthenticationError errorFromAuthenticationError:_CODE \
                                           protocolCode:nil \
                                           errorDetails:_DETAILS \
                                               userInfo:@{ NSUnderlyingErrorKey : _UNDERLYING } \
                                          correlationId:_CORRELATION]; \
    if (error) { *error = adError; }

@interface ADAuthenticationError (Internal)

/*! Generates an error for invalid method argument. */
+ (ADAuthenticationError*)errorFromArgument:(id)argument
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId;
/*! Generates an error object from an internally encountered error condition. Preserves the error
 code and domain of the original error and adds the custom details in the "errorDetails" property. */
+ (ADAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
                                  userInfo:(NSDictionary *)userInfo;

/*! Genearates an error from the code and details of an authentication error */
+ (ADAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                         correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                              userInfo:(NSDictionary *)userInfo
                                         correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails;

/*! Generates an error when an unexpected internal library conditions occurs. */
+ (ADAuthenticationError*)unexpectedInternalError:(NSString *)errorDetails
                                    correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(NSUUID *)correlationId;

/*! Generates an error from cancel operations. E.g. the user pressed "Cancel" button
 on the authorization UI page. */
+ (ADAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId;

/*! Generates an error for the case that server redirects authentication process to a non-https url */
+ (ADAuthenticationError*)errorFromNonHttpsRedirect:(NSUUID *)correlationId;

+ (ADAuthenticationError *)keychainErrorFromOperation:(NSString *)operation
                                               status:(OSStatus)status
                                        correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)errorFromHTTPErrorCode:(NSInteger)code
                                             body:(NSString *)body
                                          headers:(NSDictionary *)headers
                                    correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId
                                   userInfo:(NSDictionary*)userInfo;

/*! Adds a alternate token to an existing ADAuthentication error's userInfo dictionary */
+ (ADAuthenticationError *)errorFromExistingProtectionPolicyRequiredError:(ADAuthenticationError *) error
                                                            correlationID:(NSUUID *) correlationId
                                                                    token:(ADTokenCacheItem*) token;

/*
    Returns string representation of ADErrorCode or error code number as string, if mapping for that error is missing
 */
+ (NSString*)stringForADErrorCode:(ADErrorCode)code;

@end

