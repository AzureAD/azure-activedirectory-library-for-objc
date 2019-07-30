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

/*! Errors originating from ADAL locally. Use ADErrorCodes.h to determine the error. */
extern NSString* _Nonnull const ADAuthenticationErrorDomain;
/*! Error returned by Broker, uses the same error codes as ADAuthenticationErrorDomain. */
extern NSString* _Nonnull const ADBrokerResponseErrorDomain;
/*! Error domain for keychain errors. */
extern NSString* _Nonnull const ADKeychainErrorDomain;
/*! HTTP Error Codes */
extern NSString* _Nonnull const ADHTTPErrorCodeDomain;
/*! OAuth Server Errors */
extern NSString* _Nonnull const ADOAuthServerErrorDomain;

/*!
 Contains all http headers returned from the http error response
 */
extern NSString* _Nonnull const ADHTTPHeadersKey;
/*!
Contains the suberror code returned by the server
 */
extern NSString* _Nonnull const ADSuberrorKey;
/*!
Contains the broker version for an error returned by the broker
 */
extern NSString* _Nonnull const ADBrokerVersionKey;
/*!
 Contains the UserID for which the error was generated
 */
extern NSString* _Nonnull const ADUserIdKey;

@interface ADAuthenticationError : NSError
{
    NSString* _errorDetails;
    NSString* _protocolCode;
}

/*! The error code, returned by the server. Can be null. */
@property (readonly, nullable) NSString* protocolCode;

/*! The full details of the error. Can contain details from an inner error. */
@property (readonly, nullable) NSString* errorDetails;

@end
