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
#import "ADOAuth2Constants.h"
#import "NSURL+ADExtensions.h"
#import "ADErrorCodes.h"
#import "NSString+ADHelperMethods.h"
#import "ADWebResponse.h"
#import "ADAuthenticationSettings.h"
#import "ADHelpers.h"
#import "ADLogger+Internal.h"
#import "ADURLProtocol.h"
#import "ADWebRequest+NSURLSession.h"

@interface ADWebRequest ()

- (void)completeWithError:(NSError *)error andResponse:(ADWebResponse *)response;
- (void)send;
- (BOOL)verifyRequestURL:(NSURL *)requestURL;

@end

@implementation ADWebRequest

#pragma mark - Properties

@synthesize URL      = _requestURL;
@synthesize headers  = _requestHeaders;
@synthesize timeout  = _timeout;
@synthesize isGetRequest = _isGetRequest;
@synthesize correlationId = _correlationId;

- (NSData *)body
{
    return _requestData;
}

- (void)setBody:(NSData *)body
{
    if (body != nil) {
        if (_requestData == body) {
            return;
        }
        SAFE_ARC_RELEASE(_requestData);
        _requestData = [body copy];
    }
}

#pragma mark - Initialization

- (id)initWithURL:(NSURL *)url correlationId:(NSUUID *)correlationId
{
    if (!(self = [super init])) {
        return nil;
    }
    
    _requestURL = [url copy];
    _requestHeaders = [[NSMutableDictionary alloc] init];
    
    // Default timeout for ADWebRequest is 30 seconds
    _timeout = [[ADAuthenticationSettings sharedInstance] requestTimeOut];
    
    _correlationId = correlationId;
    SAFE_ARC_RETAIN(_correlationId);
    
    _operationQueue = [[NSOperationQueue alloc] init];
    [_operationQueue setMaxConcurrentOperationCount:1];
    
    return self;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_requestURL);
    _requestURL = nil;
    
    SAFE_ARC_RELEASE(_requestHeaders);
    _requestHeaders = nil;
    SAFE_ARC_RELEASE(_requestData);
    _requestData = nil;
    
    SAFE_ARC_RELEASE(_response);
    _response = nil;
    SAFE_ARC_RELEASE(_responseData);
    _responseData = nil;
    
    SAFE_ARC_RELEASE(_correlationId);
    _correlationId = nil;
    
    SAFE_ARC_RELEASE(_operationQueue);
    _operationQueue = nil;
    
    SAFE_ARC_RELEASE(_completionHandler);
    _completionHandler = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

// Cleans up and then calls the completion handler
- (void)completeWithError:(NSError *)error andResponse:(ADWebResponse *)response
{
    // Cleanup
    SAFE_ARC_RELEASE(_response);
    _response       = nil;
    SAFE_ARC_RELEASE(_responseData);
    _responseData   = nil;
    
    _completionHandler(error, response);
}

- (void)send:(void (^)(NSError *, ADWebResponse *))completionHandler
{
    SAFE_ARC_RELEASE(_completionHandler);
    _completionHandler = [completionHandler copy];
    
    SAFE_ARC_RELEASE(_response);
    _response          = nil;
    SAFE_ARC_RELEASE(_responseData);
    _responseData      = [[NSMutableData alloc] init];
    
    [self send];
}

- (void)resend
{
    SAFE_ARC_RELEASE(_response);
    _response          = nil;
    SAFE_ARC_RELEASE(_responseData);
    _responseData      = [[NSMutableData alloc] init];
    
    [self send];
}

- (void)send
{
    [_requestHeaders addEntriesFromDictionary:[ADLogger adalId]];
    // Correlation id:
    if (_correlationId) {
        [_requestHeaders addEntriesFromDictionary:
         @{
           OAUTH2_CORRELATION_ID_REQUEST:@"true",
           OAUTH2_CORRELATION_ID_REQUEST_VALUE:[_correlationId UUIDString]
           }];
    }
    
    // If there is request data, then set the Content-Length header
    if (_requestData != nil) {
        [_requestHeaders setValue:[NSString stringWithFormat:@"%ld", (unsigned long)_requestData.length] forKey:@"Content-Length"];
    }
    
    NSURL* requestURL = [ADHelpers addClientVersionToURL:_requestURL];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:requestURL
                                                                cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:_timeout];
    request.HTTPMethod = _isGetRequest ? @"GET" : @"POST";
    request.allHTTPHeaderFields = _requestHeaders;
    request.HTTPBody = _requestData;
    
    // For some reason, setting cutom properties in request on watchOS doesn't work properly
    //[ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:nil
                                                     delegateQueue:_operationQueue];
    
    [[session dataTaskWithRequest:request
                completionHandler:^(NSData * _Nullable data,
                                    NSURLResponse * _Nullable response,
                                    NSError * _Nullable error) {
        if(error){
            [self completeWithError:error andResponse:nil];
        }
        else {
            _response = (NSHTTPURLResponse *)response;
            [_responseData appendData:data];

            NSAssert(_response != nil, @"No HTTP Response available");
            ADWebResponse *response = [[ADWebResponse alloc] initWithResponse:_response data:_responseData];
            SAFE_ARC_AUTORELEASE(response);
            
            [self completeWithError:nil andResponse:response];
        }
    }] resume];
    SAFE_ARC_RELEASE(request);
}

- (BOOL)verifyRequestURL:(NSURL *)requestURL
{
    if (requestURL == nil)
        return NO;
    
    if (![requestURL.scheme isEqualToString:@"http"] && ![requestURL.scheme isEqualToString:@"https"])
        return NO;
    
    return YES;
}

@end
