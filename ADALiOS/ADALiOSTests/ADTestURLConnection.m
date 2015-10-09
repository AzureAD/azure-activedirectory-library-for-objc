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

#import "ADTestURLConnection.h"
#import "ADLogger.h"

@implementation ADTestRequestResponse
{
    @public
    NSURLRequest* _request;
    NSData* _responseData;
    NSURLResponse* _response;
    NSError* _error;
}

+ (ADTestRequestResponse*)request:(NSURLRequest*)request
                         response:(NSURLResponse*)urlResponse
                      reponseData:(NSData*)data
{
    ADTestRequestResponse* response = [ADTestRequestResponse new];
    
    response->_request = request;
    response->_response = urlResponse;
    response->_responseData = data;
    
    return response;
}

+ (ADTestRequestResponse*)request:(NSURLRequest *)request
                          reponse:(NSURLResponse *)urlResponse
{
    ADTestRequestResponse* response = [ADTestRequestResponse new];
    
    response->_request = request;
    response->_response = urlResponse;
    
    return response;
}

+ (ADTestRequestResponse*)request:(NSURLRequest *)request
                  repondWithError:(NSError*)error
{
    ADTestRequestResponse* response = [ADTestRequestResponse new];
    
    response->_request = request;
    response->_error = error;
    
    return response;
}

+ (ADTestRequestResponse*)requestURLString:(NSString*)requestUrlString
                         responseURLString:(NSString*)responseUrlString
                              responseCode:(NSInteger)responseCode
                          httpHeaderFields:(NSDictionary*)headerFields
                          dictionaryAsJSON:(NSDictionary*)data
{
    NSURLRequest* request = [NSURLRequest requestWithURL:[NSURL URLWithString:requestUrlString]];
    NSHTTPURLResponse* response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:responseUrlString]
                                                              statusCode:responseCode
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    NSData* responseData = [NSJSONSerialization dataWithJSONObject:data options:0 error:nil];
    
    return [ADTestRequestResponse request:request
                                 response:response
                              reponseData:responseData];
}

@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSURLConnection (TestConnectionOverride)

- (id)initWithRequest:(NSURLRequest *)request
             delegate:(id)delegate
     startImmediately:(BOOL)startImmediately
{
    return (NSURLConnection*)[[ADTestURLConnection alloc] initWithRequest:request
                                                                 delegate:delegate
                                                         startImmediately:startImmediately];
}

- (id)initWithRequest:(NSURLRequest *)request
             delegate:(id)delegate
{
    return [self initWithRequest:request delegate:delegate startImmediately:YES];
}

@end
#pragma clang diagnostic pop

@implementation ADTestURLConnection
{
    NSOperationQueue* _delegateQueue;
    NSURLRequest* _request;
    id _delegate;
}

static NSMutableArray* s_responses = nil;

+ (void)initialize
{
    s_responses = [NSMutableArray new];
}

+ (void)addExpectedRequestResponse:(ADTestRequestResponse*)requestResponse
{
    [s_responses addObject:requestResponse];
}

// If you need to test a series of requests and responses use this API
+ (void)addExpectedRequestsAndResponses:(NSArray*)requestsAndResponses
{
    [s_responses addObject:[requestsAndResponses mutableCopy]];
}

+ (ADTestRequestResponse*)removeResponseForRequest:(NSURLRequest*)request
{
    NSUInteger cResponses = [s_responses count];
    
    for (NSUInteger i = 0; i < cResponses; i++)
    {
        id obj = [s_responses objectAtIndex:i];
        ADTestRequestResponse* response = nil;
        
        if ([obj isKindOfClass:[ADTestRequestResponse class]])
        {
            response = (ADTestRequestResponse*)obj;
            
            if ([[response->_request URL] isEqual:[request URL]])
            {
                [s_responses removeObjectAtIndex:i];
                return response;
            }
        }
        
        if ([obj isKindOfClass:[NSMutableArray class]])
        {
            NSMutableArray* subResponses = [s_responses objectAtIndex:i];
            response = [subResponses objectAtIndex:0];
            
            if ([response->_request isEqual:request])
            {
                [subResponses removeObjectAtIndex:0];
                if ([subResponses count] == 0)
                {
                    [s_responses removeObjectAtIndex:i];
                }
                return response;
            }
        }
    }
    
    return nil;
}

- (id)initWithRequest:(NSURLRequest*)request delegate:(id)delegate startImmediately:(BOOL)startImmediately
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _delegate = delegate;
    _request = request;
    
    if (startImmediately)
    {
        [self start];
    }
    
    return self;
}

- (void)setDelegateQueue:(NSOperationQueue*)queue
{
    _delegateQueue = queue;
}

- (void)dispatchIfNeed:(void (^)(void))block
{
    if (_delegateQueue) {
        [_delegateQueue addOperationWithBlock:block];
    }
    else
    {
        block();
    }
}

- (void)start
{
    ADTestRequestResponse* response = [ADTestURLConnection removeResponseForRequest:_request];
    
    if (!response)
    {
        AD_LOG_ERROR_F(@"No matching response found.", NSURLErrorNotConnectedToInternet, @"request url = %@", [_request URL]);
        [self dispatchIfNeed:^{
            NSError* error = [NSError errorWithDomain:NSURLErrorDomain
                                                 code:NSURLErrorNotConnectedToInternet
                                             userInfo:nil];
            
            [_delegate connection:(NSURLConnection*)self
                 didFailWithError:error];
        }];
        
        return;
    }
    
    if (response->_error)
    {
        [self dispatchIfNeed:^{
            [_delegate connection:(NSURLConnection*)self
                 didFailWithError:response->_error];
        }];
        return;
    }
    
    if (response->_response)
    {
        [self dispatchIfNeed:^{
            [_delegate connection:(NSURLConnection*)self
               didReceiveResponse:response->_response];
        }];
    }
    
    if (response->_responseData)
    {
        [self dispatchIfNeed:^{
            [_delegate connection:(NSURLConnection*)self
                   didReceiveData:response->_responseData];
        }];
    }
    
    [self dispatchIfNeed:^{
        [_delegate connectionDidFinishLoading:(NSURLConnection*)self];
    }];
    
    return;
}

- (void)cancel
{
    
}

@end
