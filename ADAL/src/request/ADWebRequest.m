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
#import "ADWebRequest.h"
#import "ADWebResponse.h"
#import "ADAuthenticationSettings.h"
#import "ADHelpers.h"
#import "ADLogger+Internal.h"
#import "ADURLProtocol.h"
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryHttpEvent.h"

@interface ADWebRequest () <NSURLConnectionDelegate>

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
    if ( body != nil )
    {
        
        if (_requestData == body)
        {
            return;
        }
        SAFE_ARC_RELEASE(_requestData);
        _requestData = [body copy];
        
        // Add default HTTP Headers to the request: Expect
        // Note that we don't bother with Expect because iOS does not support it
        //[_requestHeaders setValue:@"100-continue" forKey:@"Expect"];
    }
}

#pragma mark - Initialization

- (id)initWithURL:(NSURL *)requestURL
    requestParams:(ADRequestParameters*)requestParams
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _requestURL        = [requestURL copy];
    _requestHeaders    = [[NSMutableDictionary alloc] init];
    
    // Default timeout for ADWebRequest is 30 seconds
    _timeout           = [[ADAuthenticationSettings sharedInstance] requestTimeOut];
    
    _correlationId     = [requestParams correlationId];
    SAFE_ARC_RETAIN(_correlationId);
    
    _telemetryRequestId = [requestParams telemetryRequestId];
    SAFE_ARC_RETAIN(_telemetryRequestId);
    
    _operationQueue = [[NSOperationQueue alloc] init];
    [_operationQueue setMaxConcurrentOperationCount:1];
    
    return self;
}


- (void)dealloc
{
    SAFE_ARC_RELEASE(_connection);
    _connection = nil;
    
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
    
    SAFE_ARC_RELEASE(_telemetryRequestId);
    _telemetryRequestId = nil;
    
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
    
    SAFE_ARC_RELEASE(_connection);
    _connection     = nil;
    
    [self stopTelemetryEvent:error response:response];
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
    [[ADTelemetry sharedInstance] startEvent:_telemetryRequestId eventName:@"http_request"];
    
    [_requestHeaders addEntriesFromDictionary:[ADLogger adalId]];
    //Correlation id:
    if (_correlationId)
    {
        [_requestHeaders addEntriesFromDictionary:
         @{
           OAUTH2_CORRELATION_ID_REQUEST:@"true",
           OAUTH2_CORRELATION_ID_REQUEST_VALUE:[_correlationId UUIDString]
           }];
    }
    // If there is request data, then set the Content-Length header
    if ( _requestData != nil )
    {
        [_requestHeaders setValue:[NSString stringWithFormat:@"%ld", (unsigned long)_requestData.length] forKey:@"Content-Length"];
    }
    
    NSURL* requestURL = [ADHelpers addClientVersionToURL:_requestURL];
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:requestURL
                                                                cachePolicy:NSURLRequestReloadIgnoringCacheData
                                                            timeoutInterval:_timeout];
    
    request.HTTPMethod          = _isGetRequest ? @"GET" : @"POST";
    request.allHTTPHeaderFields = _requestHeaders;
    request.HTTPBody            = _requestData;
    
    [ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    
    SAFE_ARC_RELEASE(_connection);
    _connection = [[NSURLConnection alloc] initWithRequest:request delegate:self startImmediately:NO];
    SAFE_ARC_RELEASE(request);
    [_connection setDelegateQueue:_operationQueue];
    [_connection start];
}

- (BOOL)verifyRequestURL:(NSURL *)requestURL
{
    if ( requestURL == nil )
        return NO;
    
    if ( ![requestURL.scheme isEqualToString:@"http"] && ![requestURL.scheme isEqualToString:@"https"] )
        return NO;
    
    return YES;
}

#pragma mark - NSURLConnectionDelegate

// Connection Authentication

// Discussion
// This method allows the delegate to make an informed decision about connection authentication at once.
// If the delegate implements this method, it has no need to implement connection:canAuthenticateAgainstProtectionSpace:, connection:didReceiveAuthenticationChallenge:, connectionShouldUseCredentialStorage:.
// In fact, these other methods are not invoked.
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
#pragma unused(connection)
    // Do default handling
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

// Connection Completion

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
#pragma unused(connection)
    
    [self completeWithError:error andResponse:nil];
}

// Method Group
- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse
{
#pragma unused(connection)
#pragma unused(cachedResponse)
    
    return nil;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
#pragma unused(connection)
    
    SAFE_ARC_RELEASE(_response);
    _response = (NSHTTPURLResponse *)response;
    SAFE_ARC_RETAIN(_response);
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
#pragma unused(connection)
    
    [_responseData appendData:data];
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse
{
#pragma unused(connection)
#pragma unused(redirectResponse)
    NSURL* requestURL = [request URL];
    NSURL* modifiedURL = [ADHelpers addClientVersionToURL:requestURL];
    if (modifiedURL == requestURL)
    {
        return request;
    }
    
    NSMutableURLRequest* mutableRequest = [NSMutableURLRequest requestWithURL:modifiedURL];
    [ADURLProtocol addCorrelationId:_correlationId toRequest:mutableRequest];
    return mutableRequest;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
#pragma unused(connection)
    
    //
    // NOTE: There is a race condition between this method and the challenge handling methods
    //       dependent on the the challenge processing that the application performs.
    //
    NSAssert( _response != nil, @"No HTTP Response available" );
    
    ADWebResponse* response = [[ADWebResponse alloc] initWithResponse:_response data:_responseData];
    SAFE_ARC_AUTORELEASE(response);
    [self completeWithError:nil andResponse:response];
}

//required method Available in OS X v10.6 through OS X v10.7, then deprecated
-(void)connection:(NSURLConnection *)connection didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite
{
#pragma unused(connection)
#pragma unused(bytesWritten)
#pragma unused(totalBytesWritten)
#pragma unused(totalBytesExpectedToWrite)
    
}

- (void)stopTelemetryEvent:(NSError *)error
                  response:(ADWebResponse *)response
{
    ADTelemetryHttpEvent* event = [[ADTelemetryHttpEvent alloc] initWithName:@"http_request" requestId:_telemetryRequestId correlationId:_correlationId];
    
    [event setHttpMethod:_isGetRequest ? @"GET" : @"POST"];
    [event setHttpPath:[NSString stringWithFormat:@"%@://%@/%@", _requestURL.scheme, _requestURL.host, _requestURL.path]];
    if (error)
    {
        [event setHttpResponseCode:[NSString stringWithFormat: @"%ld", (long)[error code]]];
        [event setHttpErrorDomain:[error domain]];
    }
    else if (response)
    {
        [event setHttpResponseCode:[NSString stringWithFormat: @"%ld", (long)[response statusCode]]];
    }
    
    [[ADTelemetry sharedInstance] stopEvent:_telemetryRequestId event:event];
    SAFE_ARC_RELEASE(event);

}

@end
