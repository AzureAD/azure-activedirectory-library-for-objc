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

#import "ADALAuthenticationError.h"
#import "ADALErrorCodes.h"
#import "ADALTokenCacheItem.h"

#define AUTH_ERROR(_CODE, _DETAILS, _CORRELATION) \
    ADALAuthenticationError* adError = \
    [ADALAuthenticationError errorFromAuthenticationError:_CODE \
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
    ADALAuthenticationError* adError = \
    [ADALAuthenticationError errorFromAuthenticationError:_CODE \
                                           protocolCode:nil \
                                           errorDetails:_DETAILS \
                                               userInfo:@{ NSUnderlyingErrorKey : _UNDERLYING } \
                                          correlationId:_CORRELATION]; \
    if (error) { *error = adError; }

@interface ADALAuthenticationError (Internal)

/*! Generates an error for invalid method argument. */
+ (ADALAuthenticationError*)errorFromArgument:(id)argument
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId;
/*! Generates an error object from an internally encountered error condition. Preserves the error
 code and domain of the original error and adds the custom details in the "errorDetails" property. */
+ (ADALAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)errorWithDomain:(NSString *)domain
                                      code:(NSInteger)code
                         protocolErrorCode:(NSString *)protocolCode
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId
                                  userInfo:(NSDictionary *)userInfo;

/*! Genearates an error from the code and details of an authentication error */
+ (ADALAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                         correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
                                              userInfo:(NSDictionary *)userInfo
                                         correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError*)errorQuietWithAuthenticationError:(NSInteger)code
                                               protocolCode:(NSString*)protocolCode
                                               errorDetails:(NSString*)errorDetails;

/*! Generates an error when an unexpected internal library conditions occurs. */
+ (ADALAuthenticationError*)unexpectedInternalError:(NSString *)errorDetails
                                    correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError*)invalidArgumentError:(NSString *)details
                                 correlationId:(NSUUID *)correlationId;

/*! Generates an error from cancel operations. E.g. the user pressed "Cancel" button
 on the authorization UI page. */
+ (ADALAuthenticationError*)errorFromCancellation:(NSUUID *)correlationId;

/*! Generates an error for the case that server redirects authentication process to a non-https url */
+ (ADALAuthenticationError*)errorFromNonHttpsRedirect:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)keychainErrorFromOperation:(NSString *)operation
                                               status:(OSStatus)status
                                        correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)errorFromHTTPErrorCode:(NSInteger)code
                                             body:(NSString *)body
                                          headers:(NSDictionary *)headers
                                    correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId;

+ (ADALAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId
                                   userInfo:(NSDictionary *)userInfo;

+ (ADALAuthenticationError *)errorFromExistingError:(ADALAuthenticationError *)error
                                    correlationID:(NSUUID *)correlationId
                               additionalUserInfo:(NSDictionary *)userInfo;

#if AD_BROKER
/*! Adds a alternate token to an existing ADAuthentication error's userInfo dictionary */
+ (ADALAuthenticationError *)errorFromExistingProtectionPolicyRequiredError:(ADALAuthenticationError *)error
                                                            correlationID:(NSUUID *)correlationId
                                                                    token:(ADALTokenCacheItem*)token;
#endif

/*
    Returns string representation of ADErrorCode or error code number as string, if mapping for that error is missing
 */
+ (NSString*)stringForADErrorCode:(ADErrorCode)code;

@end

