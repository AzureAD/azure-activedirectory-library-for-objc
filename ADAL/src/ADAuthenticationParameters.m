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

#import "ADAuthenticationParameters.h"
#import "ADAuthenticationParameters+Internal.h"
#import "ADAuthenticationSettings.h"
#import "ADWebRequest.h"
#import "ADWebResponse.h"
#import "ADAuthenticationError+Internal.h"

@implementation ADAuthenticationParameters

//These two are needed, as the instance variables will be accessed by the class category.
@synthesize authority = _authority;
@synthesize resource = _resource;

- (id)init
{
    //Throws exception as the method should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+ (void)raiseErrorWithCode:(ADErrorCode)code
                   details:(NSString *)details
                     error:(NSError * __autoreleasing *)error
{
    //The error object should always be created to ensure propper logging, even if "error" is nil.
    NSError* raisedError = MSIDCreateError(ADAuthenticationErrorDomain, code, details, nil, nil, nil, nil, nil);
    if (error)
    {
        *error = raisedError;
    }
}

- (NSDictionary*)extractedParameters
{
    return [NSDictionary dictionaryWithDictionary:_extractedParameters];
}

+ (void)parametersFromResourceUrl:(NSURL*)resourceUrl
                  completionBlock:(ADParametersCompletion)completion
{
    API_ENTRY;
    THROW_ON_NIL_ARGUMENT(completion);//The block is required
    
    if (!resourceUrl)
    {
        //Nil passed, just call the callback on the same thread with the error:
        NSString *errorMessage = [NSString stringWithFormat:@"The argument '%@' is invalid. Value:%@", @"resourceUrl", resourceUrl];
        NSError *argumentError = MSIDCreateError(ADAuthenticationErrorDomain, AD_ERROR_DEVELOPER_INVALID_ARGUMENT, errorMessage, nil, nil, nil, nil, nil);

        completion(nil, [ADAuthenticationError errorWithNSError:argumentError]);
        return;
    }

    ADWebRequest* request = [[ADWebRequest alloc] initWithURL:resourceUrl context:nil];
    [request setIsGetRequest:YES];
    MSID_LOG_VERBOSE(nil, @"Starting authorization challenge request.");
    MSID_LOG_VERBOSE_PII(nil, @"Starting authorization challenge request. Resource: %@", resourceUrl);
    
    [request send:^(NSError * error, ADWebResponse *response) {
        NSError* adError = nil;
        ADAuthenticationParameters* parameters = nil;
        if (error)
        {
            NSString *description = [NSString stringWithFormat:@"Connection error: %@", error.description];
            adError = MSIDCreateError(error.domain, error.code, description, nil, nil, nil, nil, nil);
        }
        else if (HTTP_UNAUTHORIZED != response.statusCode)
        {
            NSString *errorDescription = [NSString stringWithFormat:UnauthorizedHTTStatusExpected, response.statusCode];
            adError = MSIDCreateError(ADAuthenticationErrorDomain, AD_ERROR_SERVER_UNAUTHORIZED_CODE_EXPECTED, errorDescription, nil, nil, nil, nil, nil);
        }
        else
        {
            //Request coming, attempt to process it:
            parameters = [self parametersFromResponseHeaders:response.headers error:&adError];
        }
        completion(parameters, [ADAuthenticationError errorWithNSError:adError]);
        [request invalidate];
    }];
}

+ (ADAuthenticationParameters*)parametersFromResponseHeaders:(NSDictionary *)headers
                                                       error:(ADAuthenticationError *__autoreleasing *)error
{
    // Handle 401 Unauthorized using the OAuth2 Implicit Profile
    NSString  *authenticateHeader = [headers valueForKey:OAuth2_Authenticate_Header];
    if ([NSString msidIsStringNilOrBlank:authenticateHeader])
    {
        NSString* details = [NSString stringWithFormat:MissingHeader, OAuth2_Authenticate_Header];
        [self raiseErrorWithCode:AD_ERROR_SERVER_MISSING_AUTHENTICATE_HEADER details:details error:error];
        
        return nil;
    }
    
    MSID_LOG_INFO(nil, @"Retrieved authenticate header");
    MSID_LOG_INFO_PII(nil, @"Retrieved authenticate header: %@", authenticateHeader);
    return [self parametersFromResponseAuthenticateHeader:authenticateHeader error:error];
}

+ (ADAuthenticationParameters*)parametersFromResponse:(NSHTTPURLResponse *)response
                                                error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_ARGUMENT(response);
    
    return [self parametersFromResponseHeaders:response.allHeaderFields error:error];
}

+ (ADAuthenticationParameters *)parametersFromResponseAuthenticateHeader:(NSString *)authenticateHeader
                                                                  error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    
    NSDictionary* params = [self extractChallengeParameters:authenticateHeader error:error];
    if (!params)
    {
        return nil;
    }
    
    ADAuthenticationParameters *parameters = [[ADAuthenticationParameters alloc] initInternalWithParameters:params error:error];
    return parameters;
}


@end
