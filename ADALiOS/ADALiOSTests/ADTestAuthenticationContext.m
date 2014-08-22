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

#import "ADTestAuthenticationContext.h"
#import "../ADALiOS/ADALiOS.h"
#import "../ADALiOS/ADOAuth2Constants.h"

@implementation ADTestAuthenticationContext

-(ADTestAuthenticationContext*) initWithAuthority: (NSString*) authority
                                validateAuthority: (BOOL) validateAuthority
                                  tokenCacheStore: (id<ADTokenCacheStoring>)tokenCache
                                            error: (ADAuthenticationError* __autoreleasing *) error
{
    self = [super initWithAuthority:authority validateAuthority:validateAuthority tokenCacheStore:tokenCache error:error];
    if (self)
    {
        mResponse1 = [NSMutableDictionary new];
        mResponse2 = [NSMutableDictionary new];
        mExpectedRequest1 = [NSMutableDictionary new];
        mExpectedRequest2 = [NSMutableDictionary new];
        mAllowTwoRequests = NO;
        mNumRequests = 0;
        mReturnState = YES;
    }
    return self;
}

-(NSMutableDictionary*) getExpectedRequest
{
    return (mNumRequests == 1) ? mExpectedRequest1 : mExpectedRequest2;
}

-(NSMutableDictionary*) getResponse
{
    return (mNumRequests == 1) ? mResponse1 : mResponse2;
}

//Override of the parent's request to allow testing of the class behavior.
- (void)request:(NSString *)authorizationServer
    requestData:(NSDictionary *)request_data
requestCorrelationId: (NSUUID*) requestCorrelationId
isHandlingPKeyAuthChallenge: (BOOL) isHandlingPKeyAuthChallenge
additionalHeaders:(NSDictionary *)additionalHeaders
     completion:( void (^)(NSDictionary *) )completionBlock
{
    ++mNumRequests;
    if (mNumRequests > 2 || (!mAllowTwoRequests && mNumRequests > 1))
    {
        mErrorMessage = @"Too many server requests per single acquireToken.";
    }
    if (!requestCorrelationId)
    {
        mErrorMessage = @"Missing request correlation id.";
        completionBlock([self getResponse]);
        return;
    }
    if (!request_data || !request_data.count)
    {
        mErrorMessage = @"Nil or empty request send to the server.";
        completionBlock([self getResponse]);
        return;
    }
    
    NSString* state;
    if (1 == mNumRequests)
    {
        mCorrelationId1 = requestCorrelationId;
        state = mRequestedState1 = [request_data objectForKey:OAUTH2_STATE];
    }
    else
    {
        mCorrelationId2 = requestCorrelationId;
        state = mRequestedState2 = [request_data objectForKey:OAUTH2_STATE];
    }
    
    
    //Verify the data sent to the server:
    //The expected list will be modified in the loop below
    NSMutableDictionary* expectedRequest = [NSMutableDictionary dictionaryWithDictionary:[self getExpectedRequest]];
    for(NSString* key in [expectedRequest allKeys])
    {
        NSString* expected = [expectedRequest objectForKey:key];
        NSString* result = [request_data objectForKey:key];
        if (![result isKindOfClass:[NSString class]])
        {
            mErrorMessage = [NSString stringWithFormat:@"Requested data: Unexpected type for the key (%@): %@", key, result];
            completionBlock([self getResponse]);
            return;
        }
        if (expected.length && ![expected isEqualToString:result])//We pass empty string, when the value is not known, but the key is expected
        {
            mErrorMessage = [NSString stringWithFormat:@"Requested data: Unexpected value for the key (%@): Expected: '%@'; Actual: '%@'", key, expected, result];
            completionBlock([self getResponse]);
            return;
        }
        else if (expected)
        {
            //The expected value was found; remove it from the expected list
            [expectedRequest removeObjectForKey:key];
        }
    }
    if (expectedRequest.count)
    {
        //Some of the expected value were not present in the request:
        mErrorMessage = [NSString stringWithFormat:@"Request data: Missing expected headers: %@", expectedRequest];
    }
    
    NSMutableDictionary* responce = [self getResponse];
    if (mReturnState && state)
    {
        [responce setObject:state forKey:OAUTH2_STATE];
    }

    //If everything is ok, pass over the desired response:
    completionBlock(responce);
}

@end

