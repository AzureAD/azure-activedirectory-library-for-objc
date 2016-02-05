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

@interface ADTestURLResponse : NSObject
{
@public
    NSURL* _requestURL;
    id _requestJSONBody;
    id _requestParamsBody;
    NSDictionary* _requestHeaders;
    NSData* _requestBody;
    NSDictionary* _QPs;
    NSDictionary* _expectedRequestHeaders;
    NSData* _responseData;
    NSURLResponse* _response;
    NSError* _error;
}

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data;

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                       requestJSONBody:(id)requestJSONBody
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data;

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                        requestHeaders:(NSDictionary *)requestHeaders
                     requestParamsBody:(id)requestParams
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data;

+ (ADTestURLResponse*)request:(NSURL*)request
                     response:(NSURLResponse*)response
                  reponseData:(NSData*)data;

+ (ADTestURLResponse*)request:(NSURL *)request
                      reponse:(NSURLResponse *)response;

+ (ADTestURLResponse*)request:(NSURL *)request
              respondWithError:(NSError*)error;

+ (ADTestURLResponse*)serverNotFoundResponseForURLString:(NSString*)requestURLString;

+ (ADTestURLResponse*)responseValidAuthority:(NSString*)authority;
+ (ADTestURLResponse*)responseInvalidAuthority:(NSString*)authority;

@end

@interface ADTestURLConnection : NSObject
{
    NSOperationQueue* _delegateQueue;
    NSURLRequest* _request;
    id _delegate;
}

// This adds an expected request, and response to it.
+ (void)addResponse:(ADTestURLResponse*)response;

// If you need to test a series of requests and responses use this API
+ (void)addResponses:(NSArray*)responses;

// Helper methods for common responses
+ (void)addNotFoundResponseForURLString:(NSString*)URLString;
+ (void)addValidAuthorityResponse:(NSString*)authority;
+ (void)addInvalidAuthorityResponse:(NSString*)authority;

+ (BOOL)noResponsesLeft;
+ (void)clearResponses;

- (id)initWithRequest:(NSURLRequest*)request
             delegate:(id)delegate
     startImmediately:(BOOL)startImmediately;

@end
