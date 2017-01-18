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
#import "ADURLProtocol.h"
#import "ADLogger.h"
#import "ADNTLMHandler.h"
#import "ADCustomHeaderHandler.h"
#import "ADTelemetryUIEvent.h"
#import "ADTelemetryEventStrings.h"
#import "ADURLSessionDemux.h"


static NSMutableDictionary *s_handlers      = nil;
static NSString *s_endURL                   = nil;
static ADTelemetryUIEvent *s_telemetryEvent = nil;

static NSString* s_kADURLProtocolPropertyKey  = @"ADURLProtocol";


static NSUUID * _reqCorId(NSURLRequest* request)
{
    return [NSURLProtocol propertyForKey:@"correlationId" inRequest:request];
}


@implementation ADURLProtocol

+ (void)registerHandler:(id)handler
             authMethod:(NSString*)authMethod
{
    if (!handler || !authMethod)
    {
        return;
    }
    
    authMethod = [authMethod lowercaseString];
    
    @synchronized(self)
    {
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            s_handlers = [NSMutableDictionary new];
        });
        
        [s_handlers setValue:handler forKey:authMethod];
    }
}


+ (BOOL)registerProtocol:(NSString*)endURL
          telemetryEvent:(ADTelemetryUIEvent*)telemetryEvent
{
    if (s_endURL!=endURL)
    {
        s_endURL = endURL.lowercaseString;
        SAFE_ARC_RETAIN(s_endURL);
    }
    s_telemetryEvent = telemetryEvent;
    return [NSURLProtocol registerClass:self];
}

+ (void)unregisterProtocol
{
    [NSURLProtocol unregisterClass:self];
    SAFE_ARC_RELEASE(s_endURL);
    s_endURL = nil;
    s_telemetryEvent = nil;
    
    @synchronized(self)
    {
        for (NSString* key in s_handlers)
        {
            Class<ADAuthMethodHandler> handler = [s_handlers objectForKey:key];
            [handler resetHandler];
        }
    }
}

+ (void)addCorrelationId:(NSUUID *)correlationId
               toRequest:(NSMutableURLRequest *)request
{
    if (!correlationId)
    {
        return;
    }
    
    [NSURLProtocol setProperty:correlationId forKey:@"correlationId" inRequest:request];
}

+ (ADURLSessionDemux *)sharedDemux
{
    static dispatch_once_t      sOnceToken;
    static ADURLSessionDemux * sDemux;
    dispatch_once(&sOnceToken, ^{
        NSURLSessionConfiguration *     config;
        
        config = [NSURLSessionConfiguration defaultSessionConfiguration];
        // You have to explicitly configure the session to use your own protocol subclass here
        // otherwise you don't see redirects <rdar://problem/17384498>.

        config.protocolClasses = @[ self ];
        config.HTTPMaximumConnectionsPerHost = 1;
        
        sDemux = [[ADURLSessionDemux alloc] initWithConfiguration:config];
    });
    return sDemux;
}


#pragma mark - Overrides
+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    // If we've already handled this request, don't pick it up again
    if ([NSURLProtocol propertyForKey:s_kADURLProtocolPropertyKey inRequest:request])
    {
        return NO;
    }
    
    //TODO: Experiment with filtering of the URL to ensure that this class intercepts only
    //ADAL initiated webview traffic, INCLUDING redirects. This may have issues, if requests are
    //made from javascript code, instead of full page redirection. As such, I am intercepting
    //all traffic while authorization webview session is displayed for now.
    if ( [[request.URL.scheme lowercaseString] isEqualToString:@"https"])
    {
        
        AD_LOG_VERBOSE_F(@"+[ADURLProtocol canInitWithRequest:] handling host", _reqCorId(request), @"host: %@", [request.URL host]);
        //This class needs to handle only TLS. The check below is needed to avoid infinite recursion between starting and checking
        //for initialization
        if (![NSURLProtocol propertyForKey:s_kADURLProtocolPropertyKey inRequest:request])
        {
            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(@"+[ADURLProtocol canInitWithRequest:] ignoring handling of host - scheme is not HTTPS", _reqCorId(request), @"host: %@", [request.URL host]);
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(@"+[ADURLProtocol canonicalRequestForRequest:]", _reqCorId(request), @"host: %@", [request.URL host] );
    
    return request;
}

- (void)startLoading
{
    NSUUID* correlationId = _reqCorId(self.request);
    if (correlationId)
    {
        SAFE_ARC_RELEASE(_correlationId);
        _correlationId = correlationId;
        SAFE_ARC_RETAIN(_correlationId);
    }
    
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol startLoading]", _correlationId, @"host: %@", [self.request.URL host]);
    NSLog(@"JK => %@", [self.request.URL absoluteString]);
    NSMutableURLRequest* request = [self.request mutableCopy];
    
    // Make sure the correlation ID propogates through the requests
    if (!correlationId && _correlationId)
    {
        [ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    }
    
    [NSURLProtocol setProperty:@YES forKey:s_kADURLProtocolPropertyKey inRequest:request];
    
    _dataTask = [[[self class] sharedDemux] dataTaskWithRequest:request delegate:self];
    [_dataTask resume];
    
//    SAFE_ARC_RELEASE(_connection);
//    _connection = [[NSURLConnection alloc] initWithRequest:request
//                                                  delegate:self
//                                          startImmediately:YES];
//    SAFE_ARC_RELEASE(request);
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol stopLoading]", _reqCorId(self.request), @"host: %@", [self.request.URL host]);
    
    [_connection cancel];
    SAFE_ARC_RELEASE(_connection);
    _connection = nil;
    
    
    [_dataTask cancel];
    _dataTask = nil;
    
}


#pragma mark - NSURLSessionTaskDelegate
/* An HTTP request is attempting to perform a redirection to a different
 * URL. You must invoke the completion routine to allow the
 * redirection, allow the redirection with a modified request, or
 * pass nil to the completionHandler to cause the body of the redirection
 * response to be delivered as the payload of this request. The default
 * is to follow redirections.
 *
 * For tasks in background sessions, redirections will always be followed and this method will not be called.
 */
- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler
{
    (void)session;
    
    if ([request.URL.scheme.lowercaseString isEqualToString:@"http"])
    {
        if ([request.URL.absoluteString.lowercaseString hasPrefix:s_endURL])
        {
            [task cancel];
            NSError* failingError = [NSError errorWithDomain:NSURLErrorDomain
                                                        code:-1003
                                                    userInfo:@{ NSURLErrorFailingURLErrorKey : request.URL }];
            [self.client URLProtocol:self didFailWithError:failingError];
        }
        completionHandler(nil);
        return;
    }
    
    NSMutableURLRequest *mutableRequest = [request mutableCopy];
    
    [ADCustomHeaderHandler applyCustomHeadersTo:mutableRequest];
    [ADURLProtocol addCorrelationId:_correlationId toRequest:mutableRequest];
    
    if (!response)
    {
        // If there wasn't a redirect response that means that we're canonicalizing
        // the URL and don't need to cancel the connection or worry about an infinite
        // loop happening so we can just return the response now.
        completionHandler(mutableRequest);
    }
    
    // If we don't have this line in the redirectResponse case then we get a HTTP too many redirects
    // error.
    [NSURLProtocol removePropertyForKey:s_kADURLProtocolPropertyKey inRequest:mutableRequest];

    [self.client URLProtocol:self wasRedirectedToRequest:mutableRequest redirectResponse:response];
    
    // If we don't cancel out the connection in the redirectResponse case then we will end up
    // with duplicate connections
    
    // Here are the comments from Apple's CustomHTTPProtocol demo code:
    // https://developer.apple.com/library/ios/samplecode/CustomHTTPProtocol/Introduction/Intro.html
    
    // Stop our load.  The CFNetwork infrastructure will create a new NSURLProtocol instance to run
    // the load of the redirect.
    
    // The following ends up calling -URLSession:task:didCompleteWithError: with NSURLErrorDomain / NSURLErrorCancelled,
    // which specificallys traps and ignores the error.
    
    [task cancel];
    [self.client URLProtocol:self
            didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain
                                                 code:NSUserCancelledError
                                             userInfo:nil]];

//    completionHandler(mutableRequest);
}

/* The task has received a request specific authentication challenge.
 * If this delegate is not implemented, the session specific authentication challenge
 * will *NOT* be called and the behavior will be the same as using the default handling
 * disposition.
 */
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(ChallengeCompletionHandler)completionHandler
{
    NSString *authMethod = [challenge.protectionSpace.authenticationMethod lowercaseString];
    AD_LOG_VERBOSE_F(@"session:task:didReceiveChallenge:completionHandler", _correlationId,
                     @"%@. Previous challenge failure count: %ld", authMethod, (long)challenge.previousFailureCount);
    
    BOOL handled = NO;
    Class<ADAuthMethodHandler> handler = nil;
    @synchronized ([self class]) {
        handler = [s_handlers objectForKey:authMethod];
    }
    
    handled = [handler handleChallenge:challenge
                               session:session
                                  task:task
                              protocol:self
                     completionHandler:completionHandler];
    
    if (!handled)
    {
        // Do default handling
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    
    if ([authMethod caseInsensitiveCompare:NSURLAuthenticationMethodNTLM] == NSOrderedSame)
    {
        [s_telemetryEvent setNtlm:AD_TELEMETRY_YES];
    }
}

/* Sent as the last message related to a specific task.  Error may be
 * nil, which implies that no error occurred and this task is complete.
 */
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didCompleteWithError:(nullable NSError *)error
{
    (void)session;
    (void)task;
    
    if (error == nil)
    {
        [self.client URLProtocolDidFinishLoading:self];
    }
    else if ([error.domain isEqual:NSURLErrorDomain] && error.code == NSURLErrorCancelled)
    {
        // Do nothing. Happens in two cases
        //        // Do nothing.  This happens in two cases:
        //
        // o during a redirect, in which case the redirect code has already told the client about
        //   the failure
        //
        // o if the request is cancelled by a call to -stopLoading, in which case the client doesn't
        //   want to know about the failure
    }
    else
    {
        [self.client URLProtocol:self didFailWithError:error];
    }
}

#pragma mark - NSURLSessionDataDelegate
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler
{
    (void)session;
    (void)dataTask;
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

/* Sent when data is available for the delegate to consume.  It is
 * assumed that the delegate will retain and not copy the data.  As
 * the data may be discontiguous, you should use
 * [NSData enumerateByteRangesUsingBlock:] to access it.
 */
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    (void)session;
    (void)dataTask;
    [self.client URLProtocol:self didLoadData:data];
}
//
///* Invoke the completion routine with a valid NSCachedURLResponse to
// * allow the resulting data to be cached, or pass nil to prevent
// * caching. Note that there is no guarantee that caching will be
// * attempted for a given resource, and you should not rely on this
// * message to receive the resource data.
// */
//- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask
// willCacheResponse:(NSCachedURLResponse *)proposedResponse
// completionHandler:(void (^)(NSCachedURLResponse * _Nullable cachedResponse))completionHandler;
//
//
//
//
//
//
//



#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    (void)connection;
    
    AD_LOG_ERROR_F(@"-[ADURLProtocol connection:didFailedWithError:]", error.code, _correlationId, @"error: %@", error);
    [self.client URLProtocol:self didFailWithError:error];
}

- (void)connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSString* authMethod = [challenge.protectionSpace.authenticationMethod lowercaseString];
    
    AD_LOG_VERBOSE_F(@"connection:willSendRequestForAuthenticationChallenge:", _correlationId, @"%@. Previous challenge failure count: %ld", authMethod, (long)challenge.previousFailureCount);
    
    BOOL handled = NO;
    Class<ADAuthMethodHandler> handler = nil;
    @synchronized([self class])
    {
        handler = [s_handlers objectForKey:authMethod];
    }
    
    handled = [handler handleChallenge:challenge
                            connection:connection
                              protocol:self];
    
    if (!handled)
    {
        // Do default handling
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
        return;
    }
    
    if ([authMethod caseInsensitiveCompare:NSURLAuthenticationMethodNTLM] == NSOrderedSame)
    {
        [s_telemetryEvent setNtlm:AD_TELEMETRY_YES];
    }
}

#pragma mark - NSURLConnectionDataDelegate Methods

- (NSURLRequest *)connection:(NSURLConnection *)connection
             willSendRequest:(NSURLRequest *)request
            redirectResponse:(NSURLResponse *)redirectResponse
{
    (void)connection;
    
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol connection:willSendRequest:]", _correlationId, @"Redirect response: %@. New request:%@", redirectResponse.URL, request.URL);
    
    // Disallow HTTP for ADURLProtocol
    if ([request.URL.scheme isEqualToString:@"http"])
    {
        if ([request.URL.absoluteString.lowercaseString hasPrefix:s_endURL])
        {
            // In this case we want to create an NSURLError so we can intercept the URL in the webview
            // delegate, while still forcing the connection to cancel. This error is the same one the
            // OS sends if it's unable to connect to the host
            [connection cancel];
            NSError* failingError = [NSError errorWithDomain:NSURLErrorDomain
                                                        code:-1003
                                                    userInfo:@{ NSURLErrorFailingURLErrorKey : request.URL }];
            [self.client URLProtocol:self didFailWithError:failingError];
        }
        return nil;
    }
    
    NSMutableURLRequest* mutableRequest = [request mutableCopy];
    SAFE_ARC_AUTORELEASE(mutableRequest);
    
    [ADCustomHeaderHandler applyCustomHeadersTo:mutableRequest];
    [ADURLProtocol addCorrelationId:_correlationId toRequest:mutableRequest];

    if (!redirectResponse)
    {
        // If there wasn't a redirect response that means that we're canonicalizing
        // the URL and don't need to cancel the connection or worry about an infinite
        // loop happening so we can just return the response now.
        
        return mutableRequest;
    }
    
    // If we don't have this line in the redirectResponse case then we get a HTTP too many redirects
    // error.
    [NSURLProtocol removePropertyForKey:s_kADURLProtocolPropertyKey inRequest:mutableRequest];
    
    [self.client URLProtocol:self wasRedirectedToRequest:mutableRequest redirectResponse:redirectResponse];
    
    // If we don't cancel out the connection in the redirectResponse case then we will end up
    // with duplicate connections
    
    // Here are the comments from Apple's CustomHTTPProtocol demo code:
    // https://developer.apple.com/library/ios/samplecode/CustomHTTPProtocol/Introduction/Intro.html
    
    // Stop our load.  The CFNetwork infrastructure will create a new NSURLProtocol instance to run
    // the load of the redirect.
    
    // The following ends up calling -URLSession:task:didCompleteWithError: with NSURLErrorDomain / NSURLErrorCancelled,
    // which specificallys traps and ignores the error.
    
    [_connection cancel];
    [self.client URLProtocol:self
            didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain
                                                 code:NSUserCancelledError
                                             userInfo:nil]];
    
    return mutableRequest;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    (void)connection;
    
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    (void)connection;
    
    [self.client URLProtocol:self didLoadData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    (void)connection;
    
    [self.client URLProtocolDidFinishLoading:self];
}


@end
