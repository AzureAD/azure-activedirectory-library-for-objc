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
@public
    /* Each key-value pair of this dictionary is verified to be present in the
     request sent to the server. */
    NSMutableDictionary* mExpectedRequest1;
    /* Responds with this dictionary, if the communication is intercepted. */
    NSMutableDictionary* mResponse1;
    NSString* mRequestedState1;
    
    /* We have cases, when we do two requests to the server. This object is used for the second request. */
    NSMutableDictionary* mExpectedRequest2;
    NSMutableDictionary* mResponse2;
    NSString* mRequestedState2;
    
    NSUUID* mCorrelationId1;
    NSUUID* mCorrelationId2;
    
    /* If any error occurs during the verification, it will be stored in this string. */
    NSString* mErrorMessage;
    BOOL mAllowTwoRequests;
    int mNumRequests;
    BOOL mReturnState;//If set returns the state, exactly as requested.
}

-(ADTestAuthenticationContext*) initWithAuthority: (NSString*) authority
                                validateAuthority: (BOOL) validateAuthority
                                  tokenCacheStore: (id<ADTokenCacheStoring>)tokenCache
                                            error: (ADAuthenticationError* __autoreleasing *) error;

//Override of the parent's request to allow testing of the class behavior.
- (void)request:(NSString *)authorizationServer
    requestData:(NSDictionary *)request_data
requestCorrelationId: (NSUUID*) requestCorrelationId
isHandlingPKeyAuthChallenge: (BOOL) isHandlingPKeyAuthChallenge
additionalHeaders:(NSDictionary *)additionalHeaders
     completion:( void (^)(NSDictionary *) )completionBlock;


@end

