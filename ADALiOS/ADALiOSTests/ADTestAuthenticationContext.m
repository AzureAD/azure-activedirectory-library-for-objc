//
//  ADTestAuthenticationContext.m
//  ADALiOS
//
//  Created by Boris Vidolov on 12/23/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import "ADTestAuthenticationContext.h"
#import "ADALiOS.h"
#import "ADOAuth2Constants.h"

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
-(void)request:(NSString *)authorizationServer
   requestData:(NSDictionary *)request_data
requestCorrelationId: (NSUUID*) requestCorrelationId
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
    
    if (1 == mNumRequests)
    {
        mCorrelationId1 = requestCorrelationId;
    }
    else
    {
        mCorrelationId2 = requestCorrelationId;
    }
    
    
    //Verify the data sent to the server:
    NSMutableDictionary* expectedRequest = [self getExpectedRequest];
    for(NSString* key in [expectedRequest allKeys])
    {
        NSString* expected = [expectedRequest objectForKey:key];
        NSString* result = [request_data objectForKey:key];
        if (![result isKindOfClass:[NSString class]])
        {
            mErrorMessage = [NSString stringWithFormat:@"Unexpected type for the key (%@): %@", key, result];
            completionBlock([self getResponse]);
            return;
        }
        if (![expected isEqualToString:result])
        {
            mErrorMessage = [NSString stringWithFormat:@"Unexpected value for the key (%@): Expected: '%@'; Actual: '%@'", key, expected, result];
            completionBlock([self getResponse]);
            return;
        }
    }
    
    //If everything is ok, pass over the desired response:
    completionBlock([self getResponse]);
}

@end

