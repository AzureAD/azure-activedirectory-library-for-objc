//
//  ADTestAuthenticationContext.h
//  ADALiOS
//
//  Created by Boris Vidolov on 12/23/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import <ADALiOS/ADAuthenticationContext.h>

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
    
    /* We have cases, when we do two requests to the server. This object is used for the second request. */
    NSMutableDictionary* mExpectedRequest2;
    NSMutableDictionary* mResponse2;
    
    NSUUID* mCorrelationId1;
    NSUUID* mCorrelationId2;
    
    /* If any error occurs during the verification, it will be stored in this string. */
    NSString* mErrorMessage;
    
    BOOL mAllowTwoRequests;
    
    int mNumRequests;
}

-(ADTestAuthenticationContext*) initWithAuthority: (NSString*) authority
                                validateAuthority: (BOOL) validateAuthority
                                  tokenCacheStore: (id<ADTokenCacheStoring>)tokenCache
                                            error: (ADAuthenticationError* __autoreleasing *) error;

//Override of the parent's request to allow testing of the class behavior.
-(void)request:(NSString *)authorizationServer
   requestData:(NSDictionary *)request_data
requestCorrelationId: (NSUUID*) requestCorrelationId
    completion:( void (^)(NSDictionary *) )completionBlock;

@end

