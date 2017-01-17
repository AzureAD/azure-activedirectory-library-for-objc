// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "ADAL_Internal.h"
#import "ADTestURLConnection.h"
#import "ADLogger.h"
#import "ADAuthenticationResult.h"
#import "NSDictionary+ADExtensions.h"
#import "ADOAuth2Constants.h"

@implementation ADTestURLResponse

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
                                                         responseCode:200
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

+ (ADTestURLResponse*)responseValidDrsPayload:(NSString *)domain
                                      onPrems:(BOOL)onPrems
                passiveAuthenticationEndpoint:(NSString *)passiveAuthEndpoint
{
    NSString* validationPayloadURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                                      onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:validationPayloadURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"DeviceRegistrationService" :
                                                                            @{@"RegistrationEndpoint" : @"https://idontmatter.com/EnrollmentServer/DeviceEnrollmentWebService.svc",
                                                                              @"RegistrationResourceId" : @"urn:ms-drs:UUID"
                                                                            },
                                                                        @"AuthenticationService" :
                                                                            @{@"AuthCodeEndpoint" : @"https://idontmatter.com/adfs/oauth2/authorize",
                                                                              @"TokenEndpoint" : @"https://idontmatter.com/adfs/oauth2/token"
                                                                            },
                                                                        @"IdentityProviderService" :
                                                                            @{@"PassiveAuthEndpoint" : passiveAuthEndpoint}
                                                                        }];
    return response;
}


+ (ADTestURLResponse*)responseInvalidDrsPayload:(NSString *)domain
                                        onPrems:(BOOL)onPrems
{
    NSString* validationPayloadURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                                      onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:validationPayloadURL
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{}];
    return response;
}


+ (ADTestURLResponse*)responseUnreachableDrsService:(NSString *)domain
                                            onPrems:(BOOL)onPrems
{
    NSString* drsURL = [NSString stringWithFormat:@"%@%@/enrollmentserver/contract?api-version=1.0&x-client-Ver=" ADAL_VERSION_STRING,
                            onPrems ? @"https://enterpriseregistration." : @"https://enterpriseregistration.windows.net/", domain];
    
    return [self serverNotFoundResponseForURLString:drsURL];
}


+ (ADTestURLResponse*)responseValidWebFinger:(NSString *)passiveEndpoint
                                   authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"subject" : authority,
                                                                        @"links" : @[@{
                                                                                @"rel" : @"http://schemas.microsoft.com/rel/trusted-realm",
                                                                                @"href" : authority
                                                                                }]
                                                                        }];
    return response;
}

+ (ADTestURLResponse*)responseInvalidWebFinger:(NSString *)passiveEndpoint
                                   authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:400
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{}];
    return response;
}

+ (ADTestURLResponse*)responseInvalidWebFingerNotTrusted:(NSString *)passiveEndpoint
                                               authority:(NSString *)authority
{
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    ADTestURLResponse* response = [ADTestURLResponse requestURLString:url
                                                    responseURLString:@"https://idontmatter.com"
                                                         responseCode:200
                                                     httpHeaderFields:@{}
                                                     dictionaryAsJSON:@{@"subject" : authority,
                                                                        @"links" : @[@{
                                                                                @"rel" : @"http://schemas.microsoft.com/rel/trusted-realm",
                                                                                @"href" : @"idontmatch.com"
                                                                                }]
                                                                        }];
    return response;
}

+ (ADTestURLResponse*)responseUnreachableWebFinger:(NSString *)passiveEndpoint
                                         authority:(NSString *)authority

{
    (void)authority;
    NSURL *endpointFullUrl = [NSURL URLWithString:passiveEndpoint.lowercaseString];
    NSString *url = [NSString stringWithFormat:@"https://%@/.well-known/webfinger?resource=%@&x-client-Ver=" ADAL_VERSION_STRING, endpointFullUrl.host, authority];
    
    return [self serverNotFoundResponseForURLString:url];
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
    if (!jsonResponse)
    {
        _responseData = nil;
        return;
    }
    
    NSError* error = nil;
    NSData* responseData = [NSJSONSerialization dataWithJSONObject:jsonResponse options:0 error:&error];
    _responseData = responseData;
    
    NSAssert(_responseData, @"Invalid JSON object set for test response! %@", error);
}

- (void)setRequestURL:(NSURL*)requestURL
{

    _requestURL = requestURL;
    NSString* query = [requestURL query];
    _QPs = [NSString adIsStringNilOrBlank:query] ? nil : [NSDictionary adURLFormDecode:query];
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
    if (!requestsAndResponses)
    {
        return;
    }
    NSArray* copy = [requestsAndResponses mutableCopy];
    [s_responses addObject:copy];
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
        (void)requestURLString;
        
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
