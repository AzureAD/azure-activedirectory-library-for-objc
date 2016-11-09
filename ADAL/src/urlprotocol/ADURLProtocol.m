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

static NSMutableDictionary* s_handlers = nil;
static NSString* s_endURL = nil;

static NSString* kADURLProtocolPropertyKey = @"ADURLProtocol";


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
{
    if (s_endURL!=endURL)
    {
        s_endURL = endURL.lowercaseString;
        SAFE_ARC_RETAIN(s_endURL);
    }
    return [NSURLProtocol registerClass:self];
}

+ (void)unregisterProtocol
{
    [NSURLProtocol unregisterClass:self];
    SAFE_ARC_RELEASE(s_endURL);
    s_endURL = nil;
    
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

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    // If we've already handled this request, don't pick it up again
    if ([NSURLProtocol propertyForKey:kADURLProtocolPropertyKey inRequest:request])
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
        if (![NSURLProtocol propertyForKey:@"ADURLProtocol" inRequest:request])
        {
            

            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(@"+[ADURLProtocol canInitWithRequest:] ignoring handling of host", _reqCorId(request), @"host: %@", [request.URL host]);
    
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
    
    NSMutableURLRequest* request = [self.request mutableCopy];
    
    // Make sure the correlation ID propogates through the requests
    if (!correlationId && _correlationId)
    {
        [ADURLProtocol addCorrelationId:_correlationId toRequest:request];
    }
    
    [NSURLProtocol setProperty:@YES forKey:kADURLProtocolPropertyKey inRequest:request];
    
    SAFE_ARC_RELEASE(_connection);
    _connection = [[NSURLConnection alloc] initWithRequest:request
                                                  delegate:self
                                          startImmediately:YES];
    SAFE_ARC_RELEASE(request);
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol stopLoading]", _reqCorId(self.request), @"host: %@", [self.request.URL host]);
    
    [_connection cancel];
    SAFE_ARC_RELEASE(_connection);
    _connection = nil;
}

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
    [NSURLProtocol removePropertyForKey:kADURLProtocolPropertyKey inRequest:mutableRequest];
    
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
