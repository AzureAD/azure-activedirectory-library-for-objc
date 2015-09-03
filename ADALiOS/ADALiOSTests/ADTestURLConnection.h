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

#import <Foundation/Foundation.h>

@interface ADTestRequestResponse : NSObject

+ (ADTestRequestResponse*)requestURLString:(NSString*)requestUrlString
                         responseURLString:(NSString*)responseUrlString
                              responseCode:(NSInteger)responseCode
                          httpHeaderFields:(NSDictionary*)headerFields
                          dictionaryAsJSON:(NSDictionary*)data;

+ (ADTestRequestResponse*)request:(NSURLRequest*)request
                         response:(NSURLResponse*)response
                      reponseData:(NSData*)data;

+ (ADTestRequestResponse*)request:(NSURLRequest *)request
                          reponse:(NSURLResponse *)response;

+ (ADTestRequestResponse*)request:(NSURLRequest *)request
                  repondWithError:(NSError*)error;

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
