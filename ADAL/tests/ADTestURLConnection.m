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

#import "ADAL.h"
#import "ADTestURLConnection.h"
#import "ADLogger.h"
#import "ADAuthenticationResult.h"
#import "NSDictionary+ADExtensions.h"
#import "ADOAuth2Constants.h"

@implementation ADTestURLResponse
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

+ (ADTestURLResponse*)request:(NSURL*)request
              requestJSONBody:(NSDictionary*)requestBody
                     response:(NSURLResponse*)urlResponse
                  reponseData:(NSData*)data
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:request];
    response->_requestJSONBody = requestBody;
    response->_response = urlResponse;
    response->_responseData = data;
    
    return response;
}

+ (ADTestURLResponse*)request:(NSURL*)request
                     response:(NSURLResponse*)urlResponse
                  reponseData:(NSData*)data
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    response->_response = urlResponse;
    response->_responseData = data;
    
    return response;
}

+ (ADTestURLResponse*)request:(NSURL *)request
                      reponse:(NSURLResponse *)urlResponse
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    response->_response = urlResponse;
    
    return response;
}

+ (ADTestURLResponse*)request:(NSURL *)request
             respondWithError:(NSError*)error
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    response->_error = error;
    
    return response;
}

+ (ADTestURLResponse*)serverNotFoundResponseForURLString:(NSString *)requestURLString
{
    NSURL* requestURL = [NSURL URLWithString:requestURLString];
    ADTestURLResponse* response = [ADTestURLResponse request:requestURL
                                                     respondWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                                                         code:NSURLErrorCannotFindHost
                                                                                     userInfo:nil]];
    return response;
}

+ (ADTestURLResponse*)responseValidAuthority:(NSString *)authority
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://login.windows.net/common/discovery/instance?api-version=1.0&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, [authority lowercaseString]];
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:authorityValidationURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"tenant_discovery_endpoint" : @"totally valid!"}];
    
    return response;
}

+ (ADTestURLResponse*)responseInvalidAuthority:(NSString *)authority
{
    NSString* authorityValidationURL = [NSString stringWithFormat:@"https://login.windows.net/common/discovery/instance?api-version=1.0&authorization_endpoint=%@/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING, [authority lowercaseString]];
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:authorityValidationURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{OAUTH2_ERROR : @"I'm an OAUTH server error!",
                                                                        OAUTH2_ERROR_DESCRIPTION : @" I'm an OAUTH error description!"}];
    
    return response;
}

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    [response setJSONResponse:data];
    
    return response;
}

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                       requestJSONBody:(id)requestJSONBody
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    response->_requestJSONBody = requestJSONBody;
    [response setJSONResponse:data];
    
    return response;
}

+ (ADTestURLResponse*)requestURLString:(NSString*)requestUrlString
                        requestHeaders:(NSDictionary *)requestHeaders
                     requestParamsBody:(id)requestParams
                     responseURLString:(NSString*)responseUrlString
                          responseCode:(NSInteger)responseCode
                      httpHeaderFields:(NSDictionary*)headerFields
                      dictionaryAsJSON:(NSDictionary*)data
{
    ADTestURLResponse* response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    response->_requestHeaders = requestHeaders;
    response->_requestParamsBody = requestParams;
    [response setJSONResponse:data];
    
    return response;
}

- (void)setResponseURL:(NSString*)urlString
                  code:(NSInteger)code
          headerFields:(NSDictionary*)headerFields
{
    NSHTTPURLResponse* response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:urlString]
                                                              statusCode:code
                                                             HTTPVersion:@"1.1"
                                                            headerFields:headerFields];
    
    _response = response;
}

- (void)setJSONResponse:(id)jsonResponse
{
    NSError* error = nil;
    _responseData = [NSJSONSerialization dataWithJSONObject:jsonResponse options:0 error:&error];
    
    NSAssert(_responseData, @"Invalid JSON object set for test response! %@", error);
}

- (void)setRequestURL:(NSURL*)url
{
    _requestURL = url;
    NSString* query = [url query];
    if (![NSString adIsStringNilOrBlank:query])
    {
        _QPs = [NSDictionary adURLFormDecode:query];
    }
    else
    {
        _QPs = nil;
    }
}

- (BOOL)matchesURL:(NSURL*)url
{
    // Start with making sure the base URLs match up
    if ([[url scheme] caseInsensitiveCompare:[_requestURL scheme]] != NSOrderedSame)
    {
        return NO;
    }
    
    if ([[url host] caseInsensitiveCompare:[_requestURL host]] != NSOrderedSame)
    {
        return NO;
    }
    
    // Then the relative portions
    if ([[url relativePath] caseInsensitiveCompare:[_requestURL relativePath]] != NSOrderedSame)
    {
        return NO;
    }
    
    // And lastly, the tricky part. Query Params can come in any order so we need to process them
    // a bit instead of just a string compare
    NSString* query = [url query];
    if (![NSString adIsStringNilOrBlank:query])
    {
        NSDictionary* QPs = [NSDictionary adURLFormDecode:query];
        if (![QPs isEqualToDictionary:_QPs])
        {
            return NO;
        }
    }
    else if (_QPs)
    {
        return NO;
    }
    
    return YES;
}

- (BOOL)matchesBody:(NSData*)body
{
    if (_requestJSONBody)
    {
        NSError* error = nil;
        id obj = [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingAllowFragments error:&error];
        BOOL match = [obj isEqual:_requestJSONBody];
        return match;
    }
    
    if (_requestParamsBody)
    {
        NSString* string = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        id obj = [NSDictionary adURLFormDecode:string];
        return [obj isEqual:_requestParamsBody];
    }
    
    if (_requestBody)
    {
        return [_requestBody isEqualToData:body];
    }
    
    return YES;
}

- (BOOL)matchesHeaders:(NSDictionary*)headers
{
    if (!_requestHeaders)
    {
        return YES;
    }
    
    BOOL matches = YES;
    
    for (id key in _requestHeaders)
    {
        id header = [_requestHeaders objectForKey:key];
        id matchHeader = [headers objectForKey:key];
        if (!matchHeader)
        {
            AD_LOG_ERROR_F(@"Request is missing header", AD_FAILED, nil, @"%@", key);
            matches = NO;
        }
        else if (![header isEqual:matchHeader])
        {
            AD_LOG_ERROR_F(@"Request headers do not match", AD_FAILED, nil, @"expected: \"%@\" actual: \"%@\"", header, matchHeader);
            matches = NO;
        }
    }
    
    return matches;
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

+ (void)addResponse:(ADTestURLResponse*)requestResponse
{
    [s_responses addObject:requestResponse];
}

// If you need to test a series of requests and responses use this API
+ (void)addResponses:(NSArray*)requestsAndResponses
{
    [s_responses addObject:[requestsAndResponses mutableCopy]];
}

+ (void)addNotFoundResponseForURLString:(NSString *)URLString
{
    [self addResponse:[ADTestURLResponse serverNotFoundResponseForURLString:URLString]];
}

+ (void)addValidAuthorityResponse:(NSString *)authority
{
    [self addResponse:[ADTestURLResponse responseValidAuthority:authority]];
}

+ (void)addInvalidAuthorityResponse:(NSString *)authority
{
    [self addResponse:[ADTestURLResponse responseInvalidAuthority:authority]];
}

+ (ADTestURLResponse*)removeResponseForRequest:(NSURLRequest*)request
{
    NSUInteger cResponses = [s_responses count];
    
    NSURL* requestURL = [request URL];
    
    NSData* body = [request HTTPBody];
    NSDictionary* headers = [request allHTTPHeaderFields];
    
    for (NSUInteger i = 0; i < cResponses; i++)
    {
        id obj = [s_responses objectAtIndex:i];
        ADTestURLResponse* response = nil;
        
        if ([obj isKindOfClass:[ADTestURLResponse class]])
        {
            response = (ADTestURLResponse*)obj;
            
            if ([response matchesURL:requestURL] && [response matchesHeaders:headers] && [response matchesBody:body])
            {
                [s_responses removeObjectAtIndex:i];
                return response;
            }
        }
        
        if ([obj isKindOfClass:[NSMutableArray class]])
        {
            NSMutableArray* subResponses = [s_responses objectAtIndex:i];
            response = [subResponses objectAtIndex:0];
            
            if ([response matchesURL:requestURL] && [response matchesHeaders:headers] && [response matchesBody:body])
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
    ADTestURLResponse* response = [ADTestURLConnection removeResponseForRequest:_request];
    
    if (!response)
    {
        // This class is used in the test target only. If you're seeing this outside the test target that means you linked in the file wrong
        // take it out!
        //
        // No unit tests are allowed to hit network. This is done to ensure reliability of the test code. Tests should run quickly and
        // deterministically. If you're hitting this assert that means you need to add an expected request and response to ADTestURLConnection
        // using the ADTestRequestReponse class and add it using -[ADTestURLConnection addExpectedRequestResponse:] if you have a single
        // request/response or -[ADTestURLConnection addExpectedRequestsAndResponses:] if you have a series of network requests that you need
        // to ensure happen in the proper order.
        //
        // Example:
        //
        // ADTestRequestResponse* response = [ADTestRequestResponse requestURLString:@"https://login.windows.net/common/discovery/instance?api-version=1.0&authorization_endpoint=https://login.windows.net/omercantest.onmicrosoft.com/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING
        //                                                         responseURLString:@"https://idontknowwhatthisshouldbe.com"
        //                                                              responseCode:400
        //                                                          httpHeaderFields:@{}
        //                                                          dictionaryAsJSON:@{@"tenant_discovery_endpoint" : @"totally valid!"}];
        //
        //  [ADTestURLConnection addExpectedRequestResponse:response];
        //
        //
        //  Consult the ADTestRequestResponse class for a list of helper methods for formulating requests and responses.
        NSString* requestURLString = [[_request URL] absoluteString];
        NSAssert(response, @"did not find a matching response for %@", requestURLString);
        
        AD_LOG_ERROR_F(@"No matching response found.", NSURLErrorNotConnectedToInternet, nil, @"request url = %@", [_request URL]);
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
    
    if (response->_expectedRequestHeaders)
    {
        BOOL failed = NO;
        for (NSString* key in response->_expectedRequestHeaders)
        {
            NSString* value = [response->_expectedRequestHeaders objectForKey:key];
            NSString* requestValue = [[_request allHTTPHeaderFields] objectForKey:key];
            
            if (!requestValue)
            {
                AD_LOG_ERROR_F(@"Missing request header", AD_FAILED, nil, @"expected \"%@\" header", key);
                failed = YES;
            }
            
            if (![requestValue isEqualToString:value])
            {
                AD_LOG_ERROR_F(@"Mismatched request header", AD_FAILED, nil, @"On \"%@\" header, expected:\"%@\" actual:\"%@\"", key, value, requestValue);
                failed = YES;
            }
        }
        
        if (failed)
        {
            [self dispatchIfNeed:^{
                [_delegate connection:(NSURLConnection*)self
                     didFailWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                          code:NSURLErrorNotConnectedToInternet
                                                      userInfo:nil]];
            }];
        }
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

+ (BOOL)noResponsesLeft
{
    return s_responses.count == 0;
}

+ (void)clearResponses
{
    [s_responses removeAllObjects];
}

@end
