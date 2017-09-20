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

#import "ADTestURLResponse.h"

#import "NSDictionary+ADExtensions.h"
#import "NSDictionary+ADTestUtil.h"
#import "NSURL+ADExtensions.h"

@implementation ADTestURLResponse

+ (NSDictionary *)defaultHeaders
{
    static NSDictionary *s_defaultHeaders = nil;
    static dispatch_once_t once;
    
    dispatch_once(&once, ^{
        NSMutableDictionary* headers = [[ADLogger adalId] mutableCopy];
        
        headers[@"Accept"] = @"application/json";
        headers[@"client-request-id"] = [ADTestRequireValueSentinel sentinel];
        headers[@"return-client-request-id"] = @"true";
        
#if TARGET_OS_IPHONE
        headers[@"x-ms-PkeyAuth"] = @"1.0";
#endif
        
        // TODO: This really shouldn't be a default header...
        headers[@"Content-Type"] = @"application/x-www-form-urlencoded";
        
        s_defaultHeaders = [headers copy];
    });
    
    return s_defaultHeaders;
}

+ (ADTestURLResponse *)request:(NSURL *)request
               requestJSONBody:(NSDictionary *)requestBody
                      response:(NSURLResponse *)urlResponse
                   reponseData:(NSData *)data
{
    ADTestURLResponse * response = [ADTestURLResponse new];
    [response setRequestURL:request];
    response->_requestJSONBody = requestBody;
    response->_response = urlResponse;
    response->_responseData = data;
    [response setRequestHeaders:nil];
    
    return response;
}

+ (ADTestURLResponse *)request:(NSURL *)request
                      response:(NSURLResponse *)urlResponse
                   reponseData:(NSData *)data
{
    ADTestURLResponse * response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    response->_response = urlResponse;
    response->_responseData = data;
    [response setRequestHeaders:nil];
    
    return response;
}

+ (ADTestURLResponse *)request:(NSURL *)request
                       reponse:(NSURLResponse *)urlResponse
{
    ADTestURLResponse * response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    response->_response = urlResponse;
    [response setRequestHeaders:nil];
    
    return response;
}

+ (ADTestURLResponse *)request:(NSURL *)request
              respondWithError:(NSError *)error
{
    ADTestURLResponse * response = [ADTestURLResponse new];
    
    [response setRequestURL:request];
    [response setRequestHeaders:[ADLogger adalId]];
    response->_error = error;
    
    return response;
}

+ (ADTestURLResponse *)serverNotFoundResponseForURLString:(NSString *)requestURLString
{
    NSURL *requestURL = [NSURL URLWithString:requestURLString];
    ADTestURLResponse *response = [ADTestURLResponse request:requestURL
                                            respondWithError:[NSError errorWithDomain:NSURLErrorDomain
                                                                                 code:NSURLErrorCannotFindHost
                                                                             userInfo:nil]];
    return response;
}

+ (ADTestURLResponse *)requestURLString:(NSString*)requestUrlString
                      responseURLString:(NSString*)responseUrlString
                           responseCode:(NSInteger)responseCode
                       httpHeaderFields:(NSDictionary *)headerFields
                       dictionaryAsJSON:(NSDictionary *)data
{
    ADTestURLResponse *response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    [response setRequestHeaders:[ADLogger adalId]];
    [response setJSONResponse:data];
    
    return response;
}

+ (ADTestURLResponse *)requestURLString:(NSString*)requestUrlString
                        requestJSONBody:(id)requestJSONBody
                      responseURLString:(NSString*)responseUrlString
                           responseCode:(NSInteger)responseCode
                       httpHeaderFields:(NSDictionary *)headerFields
                       dictionaryAsJSON:(NSDictionary *)data
{
    ADTestURLResponse *response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    response->_requestJSONBody = requestJSONBody;
    [response setJSONResponse:data];
    
    return response;
}

+ (ADTestURLResponse *)requestURLString:(NSString*)requestUrlString
                         requestHeaders:(NSDictionary *)requestHeaders
                      requestParamsBody:(id)requestParams
                      responseURLString:(NSString*)responseUrlString
                           responseCode:(NSInteger)responseCode
                       httpHeaderFields:(NSDictionary *)headerFields
                       dictionaryAsJSON:(NSDictionary *)data
{
    ADTestURLResponse *response = [ADTestURLResponse new];
    [response setRequestURL:[NSURL URLWithString:requestUrlString]];
    [response setResponseURL:responseUrlString code:responseCode headerFields:headerFields];
    [response setRequestHeaders:requestHeaders];
    [response setUrlFormEncodedBody:requestParams];
    [response setJSONResponse:data];
    
    return response;
}

- (void)setResponseURL:(NSString *)urlString
                  code:(NSInteger)code
          headerFields:(NSDictionary *)headerFields
{
    NSHTTPURLResponse * response = [[NSHTTPURLResponse alloc] initWithURL:[NSURL URLWithString:urlString]
                                                               statusCode:code
                                                              HTTPVersion:@"1.1"
                                                             headerFields:headerFields];
    
    _response = response;
}

- (void)setResponseJSON:(id)jsonResponse
{
    [self setJSONResponse:jsonResponse];
}

- (void)setJSONResponse:(id)jsonResponse
{
    if (!jsonResponse)
    {
        _responseData = nil;
        return;
    }
    
    NSError *error = nil;
    NSData *responseData = [NSJSONSerialization dataWithJSONObject:jsonResponse options:0 error:&error];
    _responseData = responseData;
    
    NSAssert(_responseData, @"Invalid JSON object set for test response! %@", error);
}

- (void)setResponseData:(NSData *)response
{
    _responseData = response;
}

- (void)setRequestURL:(NSURL *)requestURL
{
    
    _requestURL = requestURL;
    NSString *query = [requestURL query];
    _QPs = [NSString adIsStringNilOrBlank:query] ? nil : [NSDictionary adURLFormDecode:query];
}

- (void)setRequestHeaders:(NSDictionary *)headers
{
    if (headers)
    {
        _requestHeaders = [headers mutableCopy];
    }
    else
    {
        _requestHeaders = [NSMutableDictionary new];
    }
    
    // These values come from ADClientMetrics and are dependent on a previous request, which breaks
    // the isolation of the tests. For now the easiest path is to ignore them entirely.
    if (!_requestHeaders[@"x-client-last-endpoint"])
    {
        _requestHeaders[@"x-client-last-error"] = [ADTestIgnoreSentinel sentinel];
        _requestHeaders[@"x-client-last-endpoint"] = [ADTestIgnoreSentinel sentinel];
        _requestHeaders[@"x-client-last-request"] = [ADTestIgnoreSentinel sentinel];
        _requestHeaders[@"x-client-last-response-time"] = [ADTestIgnoreSentinel sentinel];
    }
}

- (void)setRequestBody:(NSData *)body
{
    _requestBody = body;
}

- (void)setUrlFormEncodedBody:(NSDictionary *)formParameters
{
    _requestParamsBody = nil;
    if (!formParameters)
    {
        return;
    }
    
    _requestParamsBody = formParameters;
    if (!_requestHeaders)
    {
        _requestHeaders = [NSMutableDictionary new];
    }
    
    _requestHeaders[@"Content-Type"] = @"application/x-www-form-urlencoded";
    NSString *urlEncoded = [formParameters adURLFormEncode];
    _requestHeaders[@"Content-Length"] = [NSString stringWithFormat:@"%lu", (unsigned long)[urlEncoded lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
}

- (void)setWaitSemaphore:(dispatch_semaphore_t)sem
{
    _waitSemaphore = sem;
}

- (BOOL)matchesURL:(NSURL *)url
           headers:(NSDictionary *)headers
              body:(NSData *)body
{
    // We don't want the compiler to short circuit this out so that ways we print out all of the
    // things in the response that doesn't match.
    BOOL ret = YES;
    ret = [self matchesURL:url] ? ret : NO;
    ret = [self matchesHeaders:headers] ? ret : NO;
    ret = [self matchesBody:body] ? ret : NO;
    return ret;
}

- (BOOL)matchesURL:(NSURL *)url
{
    // Start with making sure the base URLs match up
    if ([url.scheme caseInsensitiveCompare:_requestURL.scheme] != NSOrderedSame)
    {
        return NO;
    }
    
    if ([[url adHostWithPortIfNecessary] caseInsensitiveCompare:[_requestURL adHostWithPortIfNecessary]] != NSOrderedSame)
    {
        return NO;
    }
    
    // Then the relative portions
    if ([url.relativePath caseInsensitiveCompare:_requestURL.relativePath] != NSOrderedSame)
    {
        return NO;
    }
    
    // And lastly, the tricky part. Query Params can come in any order so we need to process them
    // a bit instead of just a string compare
    NSString *query = [url query];
    if (![NSString adIsStringNilOrBlank:query])
    {
        NSDictionary *QPs = [NSDictionary adURLFormDecode:query];
        if (![_QPs compareAndPrintDiff:QPs dictionaryDescription:@"URL QPs"])
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

- (BOOL)matchesBody:(NSData *)body
{
    if (_requestJSONBody)    {
        NSError* error = nil;
        id obj = [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingAllowFragments error:&error];
        BOOL match = [obj isEqual:_requestJSONBody];
        return match;
    }
    
    if (_requestParamsBody)
    {
        NSString * string = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        NSDictionary *obj = [NSDictionary adURLFormDecode:string];
        return [_requestParamsBody compareAndPrintDiff:obj dictionaryDescription:@"URL Encoded Body Parameters"];
    }
    
    if (_requestBody)
    {
        return [_requestBody isEqualToData:body];
    }
    
    return YES;
}

- (BOOL)matchesHeaders:(NSDictionary *)headers
{
    if (!_requestHeaders)
    {
        if (!headers || headers.count == 0)
        {
            return YES;
        }
        // This wiil spit out to console the extra stuff that we weren't expecting
        [@{} compareAndPrintDiff:headers dictionaryDescription:@"Request Headers"];
        return NO;
    }
    
    return [_requestHeaders compareAndPrintDiff:headers dictionaryDescription:@"Request Headers"];
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@: %@>", NSStringFromClass(self.class), _requestURL];
}

@end
