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

#import "ADOAuth2Constants.h"
#import "NSURL+ADExtensions.h"
#import "ADErrorCodes.h"
#import "ADAuthenticationSettings.h"
#import "ADWebRequest.h"
#import "ADWebResponse.h"

NSString *const HTTPGet  = @"GET";
NSString *const HTTPPost = @"POST";

static NSOperationQueue *s_queue;

@interface ADWebRequest () <NSURLConnectionDelegate>

- (void)completeWithError:(NSError *)error andResponse:(ADWebResponse *)response;
- (void)send;
- (BOOL)verifyRequestURL:(NSURL *)requestURL;

@end

@implementation ADWebRequest

#pragma mark - Properties

@synthesize URL      = _requestURL;
@synthesize headers  = _requestHeaders;
@synthesize method   = _requestMethod;
@synthesize timeout  = _timeout;

- (NSData *)body
{
    return _requestData;
}

- (void)setBody:(NSData *)body
{
    if ( body != nil )
    {
        _requestMethod = HTTPPost;
        _requestData   = SAFE_ARC_RETAIN(body);
        
        // Add default HTTP Headers to the request: Expect
        // Note that we don't bother with Expect because iOS does not support it
        //[_requestHeaders setValue:@"100-continue" forKey:@"Expect"];
    }
}

#pragma mark - Initialization

+ (void)initialize
{
    s_queue = [[NSOperationQueue alloc] init];

}

- (void)dealloc
{
    AD_LOG_VERBOSE(@"ADWebRequest", @"dealloc");
    
    SAFE_ARC_RELEASE(_correlationId);
    
    SAFE_ARC_RELEASE(_requestData);
    SAFE_ARC_RELEASE(_requestHeaders);
    SAFE_ARC_RELEASE(_requestMethod);
    SAFE_ARC_RELEASE(_requestURL);
    
    SAFE_ARC_RELEASE(_response);
    SAFE_ARC_RELEASE(_responseData);
    
    SAFE_ARC_BLOCK_RELEASE(_completionHandler);
    
    SAFE_ARC_RELEASE(_connection);
    
    SAFE_ARC_SUPER_DEALLOC();
}

- (id)initWithURL: (NSURL*) requestURL
    correlationId: (NSUUID*) correlationId
{
    THROW_ON_CONDITION_ARGUMENT(![self verifyRequestURL:requestURL], requestURL);//Should have been checked by the caller
    
    self = [super init];
    if ( nil != self )
    {
        _connection        = nil;
        
        _requestURL        = [requestURL copy];
        _requestMethod     = HTTPGet;
        _requestHeaders    = [[NSMutableDictionary alloc] init];
        _requestData       = nil;
        
        _response          = nil;
        _responseData      = nil;
        
        // Default timeout for ADWebRequest is 30 seconds 
        _timeout           = [[ADAuthenticationSettings sharedInstance] requestTimeOut];
        
        _completionHandler = nil;
        _correlationId     = SAFE_ARC_RETAIN(correlationId);
        queue = [[NSOperationQueue alloc] init];
        
    }
    
    return self;
}

// Cleans up and then calls the completion handler
- (void)completeWithError:(NSError *)error andResponse:(ADWebResponse *)response
{
    if ( _completionHandler != nil )
    {
        _completionHandler( error, response );
    }
}

- (void)send:(void (^)(NSError *, ADWebResponse *))completionHandler
{
    _completionHandler = SAFE_ARC_BLOCK_COPY(completionHandler);
    
    _response          = nil;
    _responseData      = [[NSMutableData alloc] init];
    
    [self send];
}

- (void)send
{
    // Add default HTTP Headers to the request: Host
    [_requestHeaders setValue:[_requestURL adAuthority] forKey:@"Host"];
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
    
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:_requestURL
                                                                cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                            timeoutInterval:_timeout];
    
    request.HTTPMethod          = _requestMethod;
    request.allHTTPHeaderFields = _requestHeaders;
    request.HTTPBody            = _requestData;
    
    _connection = [[NSURLConnection alloc] initWithRequest:request delegate:self startImmediately:NO];
    [_connection setDelegateQueue:s_queue];
    [_connection start];
    
    SAFE_ARC_RELEASE(request);
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
    
    _response = (NSHTTPURLResponse *)SAFE_ARC_RETAIN( response );
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
    
    // Allow redirects
    return request;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
#pragma unused(connection)
    
    //
    // NOTE: There is a race condition between this method and the challenge handling methods
    //       dependent on the the challenge processing that the application performs.
    //
    NSAssert( _response != nil, @"No HTTP Response available" );
    
    ADWebResponse *response = [[ADWebResponse alloc] initWithResponse:_response data:_responseData];

    [self completeWithError:nil andResponse:response];
    
    SAFE_ARC_RELEASE(response);
}

//required method Available in OS X v10.6 through OS X v10.7, then deprecated
-(void)connection:(NSURLConnection *)connection didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite
{
#pragma unused(connection)
#pragma unused(bytesWritten)
#pragma unused(totalBytesWritten)
#pragma unused(totalBytesExpectedToWrite)
    
}

//– connection:needNewBodyStream

@end
