//
//  ADTestURLConnection.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 9/2/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADTestRequestResponse

+ (ADTestRequestResponse*)request:(NSURL*)requestUrl
                          reponse:(NSData*)data;

@end

@interface ADTestURLConnection : NSObject

// This adds an expected request, and response to it.
+ (void)addExpectedRequestResponse:(ADTestRequestResponse*)requestResponse;

// If you need to test a series of requests and responses use this API
+ (void)addExpectedRequestsAndResponses:(NSArray*)requestsAndResponses;


- (id)initWithRequest:(NSURLRequest*)request
             delegate:(id)delegate
     startImmediately:(BOOL)startImmediately;

@end
