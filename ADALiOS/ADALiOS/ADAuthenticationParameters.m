// Created by Boris Vidolov on 10/10/13.
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

#import "ADALiOS.h"
#import "ADAuthenticationParameters+Internal.h"
#import "ADAuthenticationSettings.h"


@implementation ADAuthenticationParameters

//These two are needed, as the instance variables will be accessed by the class category.
@synthesize authority = _authority;
@synthesize resource = _resource;

-(id) init
{
    //Throws exception as the method should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

+(void) raiseErrorWithCode: (ADErrorCode) code
                   details: (NSString*) details
                     error: (ADAuthenticationError* __autoreleasing*) error
{
    //The error object should always be created to ensure propper logging, even if "error" is nil.
    ADAuthenticationError* raisedError = [ADAuthenticationError errorFromUnauthorizedResponse:code errorDetails:details];
    if (error)
    {
        *error = raisedError;
    }
}

-(NSDictionary*) getExtractedParameters
{
    return [NSDictionary dictionaryWithDictionary:_extractedParameters];
}

+(void) parametersFromResourceUrl:(NSURL*)resourceUrl
                  completionBlock:(ADParametersCompletion)completion
{
    API_ENTRY;
    THROW_ON_NIL_ARGUMENT(completion);//The block is required
    
    if (!resourceUrl)
    {
        //Nil passed, just call the callback on the same thread with the error:
        ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:resourceUrl argumentName:@"resourceUrl"];
        completion(nil, error);
        return;
    }
    
    NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.timeoutIntervalForRequest = [ADAuthenticationSettings sharedInstance].requestTimeOut;
    config.timeoutIntervalForResource = [ADAuthenticationSettings sharedInstance].requestTimeOut;

    NSURLSession* session = [NSURLSession sessionWithConfiguration:config];
    NSURLSessionDataTask* task = [session dataTaskWithURL:resourceUrl completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error)
        {
            completion(nil, [ADAuthenticationError errorFromNSError:error
                                                       errorDetails:[NSString stringWithFormat:ConnectionError, error.description]]);
            return;
        }
        if (!response || ![response isKindOfClass:[NSHTTPURLResponse class]])
        {
            completion(nil, [ADAuthenticationError errorFromUnauthorizedResponse:AD_ERROR_CONNECTION_MISSING_RESPONSE
                                                                    errorDetails:InvalidResponse]);
            return;
        }
        NSHTTPURLResponse *urlResponse = (NSHTTPURLResponse*)response;
        long code = [urlResponse statusCode];
        if (HTTP_UNAUTHORIZED != code)
        {
            completion(nil, [ADAuthenticationError errorFromUnauthorizedResponse:AD_ERROR_UNAUTHORIZED_CODE_EXPECTED
                                                                    errorDetails:[NSString stringWithFormat:UnauthorizedHTTStatusExpected, code]]);
            return;
        }
        
        ADAuthenticationError* authenticationError;
        ADAuthenticationParameters* parameters = [self parametersFromResponse:urlResponse error:&authenticationError];
        completion(parameters, authenticationError);
    }];
    [task resume];
}

+(ADAuthenticationParameters*) parametersFromResponse:(NSHTTPURLResponse*)response
                                                error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_ARGUMENT(response);

    // Handle 401 Unauthorized using the OAuth2 Implicit Profile
    NSString  *authenticateHeader = [response.allHeaderFields valueForKey:OAuth2_Authenticate_Header];
    if ([NSString isStringNilOrBlank:authenticateHeader])
    {
        NSString* details = [NSString stringWithFormat:MissingHeader, OAuth2_Authenticate_Header];
        [self raiseErrorWithCode:AD_ERROR_MISSING_AUTHENTICATE_HEADER details:details error:error];

        return nil;
    }
    
    AD_LOG_INFO(@"Retrieved authenticate header", authenticateHeader);
    return [self parametersFromResponseAuthenticateHeader:authenticateHeader error:error];
}

+(ADAuthenticationParameters*) parametersFromResponseAuthenticateHeader:(NSString*)authenticateHeader
                                                                  error:(ADAuthenticationError *__autoreleasing *)error
{
    API_ENTRY;
    RETURN_NIL_ON_NIL_EMPTY_ARGUMENT(authenticateHeader);
    
    long start = [self extractChallenge:authenticateHeader error:error];//Method will set detected errors and return nil in that case
    if (start < 0)
    {
        //An error occurred:
        return nil;
    }
    
    ADAuthenticationParameters* toReturn =
        [[ADAuthenticationParameters alloc] initInternalWithChallenge:authenticateHeader start:start];
    
    if (!toReturn || [NSString isStringNilOrBlank:toReturn.authority])
    {
        //Failed to extract authority. Return error:
        NSString* details = [NSString stringWithFormat:MissingAuthority, OAuth2_Authenticate_Header, OAuth2_Authorization_Uri];
        [self raiseErrorWithCode:AD_ERROR_AUTHENTICATE_HEADER_BAD_FORMAT details:details error:error];
        
        return nil;
    }
    
    if (error)
        *error = nil;
    return toReturn;
}


@end
