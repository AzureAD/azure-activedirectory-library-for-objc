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

@interface ADWebRequest () <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>

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
    
    [ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:self
                                                     delegateQueue:_operationQueue];
    [[session dataTaskWithRequest:request] resume];
}

- (BOOL)verifyRequestURL:(NSURL *)requestURL
{
    if (requestURL == nil)
        return NO;
    
    if (![requestURL.scheme isEqualToString:@"http"] && ![requestURL.scheme isEqualToString:@"https"])
        return NO;
    
    return YES;
}

#pragma mark - NSURLSessionDelegate

-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
#pragma unused(session)
#pragma unused(task)
    
    if (!error) {
        //
        // NOTE: There is a race condition between this method and the challenge handling methods
        //       dependent on the the challenge processing that the application performs.
        //
        NSAssert(_response != nil, @"No HTTP Response available");
        
        ADWebResponse *response = [[ADWebResponse alloc] initWithResponse:_response data:_responseData];
        SAFE_ARC_AUTORELEASE(response);
        
        [self completeWithError:nil andResponse:response];
    }
    else {
        [self completeWithError:error andResponse:nil];
    }
}

-(void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
#pragma unused(session)
#pragma unused(dataTask)
#pragma unused(completionHandler)
    
    SAFE_ARC_RELEASE(_response)
    _response = (NSHTTPURLResponse *)response;
    SAFE_ARC_RETAIN(_response)
}

-(void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data
{
#pragma unused(session)
#pragma unused(dataTask)
    
    [_responseData appendData:data];
}

-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler
{
#pragma unused(session)
#pragma unused(task)
#pragma unused(response)
#pragma unused(completionHandler)
    
    NSURL *requestURL = [request URL];
    NSURL *modifiedURL = [ADHelpers addClientVersionToURL:requestURL];
    if (modifiedURL == requestURL) {
        completionHandler(request);
    }
    else {
        NSMutableURLRequest *mutableRequest = [NSMutableURLRequest requestWithURL:modifiedURL];
        [ADURLProtocol addCorrelationId:_correlationId toRequest:mutableRequest];
        completionHandler(mutableRequest);
    }
}

@end
