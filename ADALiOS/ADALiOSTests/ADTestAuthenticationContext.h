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

#import "../ADALiOS/ADAuthenticationContext.h"

//Test class that intercepts the server communication. The iVars are all public
//and intended to be directly manipulated by the tests.
@interface ADTestAuthenticationContext : ADAuthenticationContext
{
@private
    /* Each key-value pair of this dictionary is verified to be present in the
     request sent to the server. */
    NSMutableArray* _responses;
    NSMutableArray* _expectedRequests;
    NSMutableArray* _states;
    
    NSString* _errorMessage;
    
    int mNumRequests;
}

- (void)queueExpectedRequest:(NSDictionary*)expectedRequest
                    response:(NSDictionary*)response;

- (NSString*)errorMessage;

- (ADTestAuthenticationContext*)initWithAuthority:(NSString*)authority
                                validateAuthority:(BOOL)validateAuthority
                                  tokenCacheStore:(id<ADTokenCacheStoring>)tokenCache
                                            error:(ADAuthenticationError* __autoreleasing *) error;

//Override of the parent's request to allow testing of the class behavior.
- (void)requestWithServer:(NSString *)authorizationServer
              requestData:(NSDictionary *)request_data
     requestCorrelationId:(NSUUID*)requestCorrelationId
          handledPkeyAuth:(BOOL)isHandlingPKeyAuthChallenge
        additionalHeaders:(NSDictionary *)additionalHeaders
               completion:( void (^)(NSDictionary *) )completionBlock;


@end

