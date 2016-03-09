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

#import <Foundation/Foundation.h>

extern NSString* const ADAuthenticationErrorDomain;
/*! Incorrect argument passed */
extern NSString* const ADInvalidArgumentDomain;
/*! Error related to extracting authority from the 401 (Unauthorized) challenge response */
extern NSString* const ADUnauthorizedResponseErrorDomain;
/*! Error returned by Broker */
extern NSString* const ADBrokerResponseErrorDomain;
/*! Error domain for keychain errors. */
extern NSString* const ADKeychainErrorDomain;
/*! HTTP Error Codes */
extern NSString* const ADHTTPErrorCodeDomain;
/*! OAuth Server Errors */
extern NSString* const ADOAuthServerErrorDomain;

@interface ADAuthenticationError : NSError
{
    NSString* _errorDetails;
    NSString* _protocolCode;
}

/*! The error code, returned by the server. Can be null. */
@property (readonly) NSString* protocolCode;

/*! The full details of the error. Can contain details from an inner error. */
@property (readonly) NSString* errorDetails;

/*! Generates an error for invalid method argument. */
+ (ADAuthenticationError*)errorFromArgument:(id)argument
                               argumentName:(NSString *)argumentName
                              correlationId:(NSUUID *)correlationId;

/*! Generates an error related to the 401 Bearer challenge handling */
+ (ADAuthenticationError*)errorFromUnauthorizedResponse:(NSInteger)responseCode
                                           errorDetails:(NSString *)errorDetails
                                          correlationId:(NSUUID *)correlationId;

/*! Generates an error object from an internally encountered error condition. Preserves the error
 code and domain of the original error and adds the custom details in the "errorDetails" property. */
+ (ADAuthenticationError*)errorFromNSError:(NSError *)error
                              errorDetails:(NSString *)errorDetails
                             correlationId:(NSUUID *)correlationId;

/*! Genearates an error from the code and details of an authentication error */
+ (ADAuthenticationError*)errorFromAuthenticationError:(NSInteger)code
                                          protocolCode:(NSString *)protocolCode
                                          errorDetails:(NSString *)errorDetails
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

+ (ADAuthenticationError *)HTTPErrorCode:(NSInteger)code
                                    body:(NSString *)body
                           correlationId:(NSUUID *)correlationId;

+ (ADAuthenticationError *)OAuthServerError:(NSString *)protocolCode
                                description:(NSString *)description
                                       code:(NSInteger)code
                              correlationId:(NSUUID *)correlationId;

@end
