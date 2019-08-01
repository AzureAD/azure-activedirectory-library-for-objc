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

@class ADAuthenticationError;

/*! Contains authentication parameters based on unauthorized
 response from resource server */
@interface ADAuthenticationParameters : NSObject
{
    @protected
    NSDictionary* _extractedParameters;
    NSString* _authority;
    NSString* _resource;
}

/*! The extracted authority. */
@property (readonly, nullable) NSString *authority;

/*! The resource, as returned by the server. */
@property (readonly, nullable) NSString *resource;

/*! All parameters that were extracted from the authentication challenge */
@property (readonly, nullable) NSDictionary *extractedParameters;

/*!
    @param  parameters  The authentication parameters from the challenge presented by the resource,
                        nil if an error occurred
    @param  error       An ADAuthenticationError object with error details.
*/
typedef void (^ADParametersCompletion)(ADAuthenticationParameters * _Nullable parameters, ADAuthenticationError * _Nullable error);

/*!
    Creates authentication parameters from the response received from the resource. The method
    creates an HTTP GET request and expects the resource to have unauthorized status (401) and "WWW-Authenticate"
    header, containing authentication parameters.
 
    @param  response    The response received from the server with the requirements above. May return null if
                        an error has occurred.
    @param  error       Can be nil. If this parameter is not nil and an error occurred, it will be set to
                        contain the error
 */
+ (nullable ADAuthenticationParameters *)parametersFromResponse:(nonnull NSHTTPURLResponse *)response
                                                          error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;

/*!
    Creates authentication parameters from "WWW-Authenticate" header of the response received
    from the resource. The method expects the header to contain authentication parameters.
 
    @param  authenticateHeader  The http response header, containing the authentication parameters.
    @param  error               Can be nil. If this parameter is not nil and an error occurred, it will be set to
                                contain the error
 */
+ (nullable ADAuthenticationParameters *)parametersFromResponseAuthenticateHeader:(nonnull NSString *)authenticateHeader
                                                                            error:(ADAuthenticationError * __autoreleasing _Nullable * _Nullable)error;

/*!
    Extracts the authority from the the error code 401 http error code response. The method
    expects that the resource will respond with a HTTP 401 and "WWW-Authenticate" header, containing the
    authentication parameters.
 
    @param  resourceUrl     The address of the resource.
    @param  completionBlock The callback block to be executed upon completion.
 */
+ (void)parametersFromResourceUrl:(nonnull NSURL *)resourceUrl
                  completionBlock:(nonnull ADParametersCompletion)completionBlock;

@end
