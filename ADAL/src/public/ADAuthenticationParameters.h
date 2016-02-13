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

/*! The extracted authority. Can be null in case of an error. See the status field */
@property (readonly) NSString* authority;

/*! The resource URI, as returned by the server. */
@property (readonly) NSString* resource;

@property (readonly) NSDictionary* extractedParameters;

/*! The completion block declaration. In case of success, NSException parameter is nil and ADAuthenticationParameters
 is a valid pointer. If an error occurs, ADAuthenticationParameters will be nil and the NSException parameter
 contains all of the details.
*/
typedef void (^ADParametersCompletion)(ADAuthenticationParameters* parameters, ADAuthenticationError* error);

/*! Creates authentication parameters from the response received from the resource. The method 
 creates an HTTP GET request and expects the resource to have unauthorized status (401) and "WWW-Authenticate" 
 header, containing authentication parameters.
 @param: response: the response received from the server with the requirements above. May return null if
 an error has occurred.
 @param: error: Can be nil. If this parameter is not nil and an error occurred, it will be set to
 contain the error
 */
+(ADAuthenticationParameters*) parametersFromResponse: (NSHTTPURLResponse*) response
                                                error: (ADAuthenticationError*__autoreleasing*) error;

/*! Creates authentication parameters from "WWW-Authenticate" header of the response received
 from the resource. The method expects the header to contain authentication parameters.
 @param: authenticateHeader: the http response header, containing the authentication parameters.
 @param: error: Can be nil. If this parameter is not nil and an error occurred, it will be set to
 contain the error
 */
+(ADAuthenticationParameters*) parametersFromResponseAuthenticateHeader: (NSString*) authenticateHeader
                                                                  error: (ADAuthenticationError*__autoreleasing*) error;

/*! Extracts the authority from the the error code 401 http error code response. The method
 expects that the resource will respond with a HTTP 401 and "WWW-Authenticate" header, containing the
 authentication parameters.
 @param resourceUrl: address of the resource.
 @param completionBlock: the callback block to be executed upon completion.
 */
+(void) parametersFromResourceUrl: (NSURL*)resourceUrl
                  completionBlock: (ADParametersCompletion) completion;

/*! Returns a readonly copy of the extracted parameters from the authenticate header. */
-(NSDictionary*) extractedParameters;

@end
