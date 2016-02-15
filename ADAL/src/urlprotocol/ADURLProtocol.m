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

static NSString* const sLog = @"HTTP Protocol";
static NSMutableDictionary* s_handlers = nil;


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


+ (BOOL)registerProtocol
{
    return [NSURLProtocol registerClass:self];
}

+ (void)unregisterProtocol
{
    [NSURLProtocol unregisterClass:self];
    
    @synchronized(self)
    {
        for (NSString* key in s_handlers)
        {
            Class<ADAuthMethodHandler> handler = [s_handlers objectForKey:key];
            [handler resetHandler];
        }
    }
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    //TODO: Experiment with filtering of the URL to ensure that this class intercepts only
    //ADAL initiated webview traffic, INCLUDING redirects. This may have issues, if requests are
    //made from javascript code, instead of full page redirection. As such, I am intercepting
    //all traffic while authorization webview session is displayed for now.
    if ( [[request.URL.scheme lowercaseString] isEqualToString:@"https"] )
    {
        //This class needs to handle only TLS. The check below is needed to avoid infinite recursion between starting and checking
        //for initialization
        if ( [NSURLProtocol propertyForKey:@"ADURLProtocol" inRequest:request] == nil )
        {
            AD_LOG_VERBOSE_F(sLog, nil, @"Requested handling of URL host: %@", [request.URL host]);

            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(sLog, nil, @"Ignoring handling of URL host: %@", [request.URL host]);
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(sLog, nil, @"canonicalRequestForRequest host: %@", [request.URL host] );
    
    return request;
}

- (void)startLoading
{
    if (!self.request)
    {
        AD_LOG_WARN(sLog, nil, @"startLoading called without specifying the request.");
        return;
    }
    
    [self startLoading:self.request.URL];
}

- (void)startLoading:(NSURL*)url
{
    AD_LOG_VERBOSE_F(sLog, nil, @"startLoading host: %@", [url host] );
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];
    [mutableRequest setURL:url];
    [NSURLProtocol setProperty:@"YES" forKey:@"ADURLProtocol" inRequest:mutableRequest];
    _connection = [[NSURLConnection alloc] initWithRequest:mutableRequest
                                                  delegate:self
                                          startImmediately:YES];
    SAFE_ARC_RELEASE(mutableRequest);
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(sLog, nil, @"Stop loading");
    [_connection cancel];
    [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil]];
}

#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    (void)connection;
    
    AD_LOG_VERBOSE_F(sLog, nil, @"connection:didFaileWithError: %@", error);
    [self.client URLProtocol:self didFailWithError:error];
}

- (void)connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSString* authMethod = [challenge.protectionSpace.authenticationMethod lowercaseString];
    
    AD_LOG_VERBOSE_F(sLog, nil, @"connection:willSendRequestForAuthenticationChallenge: %@. Previous challenge failure count: %ld", authMethod, (long)challenge.previousFailureCount);
    
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

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)response
{
    (void)connection;
    
    AD_LOG_VERBOSE_F(sLog, nil, @"HTTPProtocol::connection:willSendRequest:. Redirect response: %@. New request:%@", response.URL, request.URL);
    //Ensure that the webview gets the redirect notifications:
    NSMutableURLRequest* mutableRequest = [request mutableCopy];
    SAFE_ARC_AUTORELEASE(mutableRequest);
    if (response)
    {
        [[self class] removePropertyForKey:@"ADURLProtocol" inRequest:mutableRequest];
        [self.client URLProtocol:self wasRedirectedToRequest:mutableRequest redirectResponse:response];
        
        [_connection cancel];
        [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil]];
        [ADCustomHeaderHandler applyCustomHeadersTo:mutableRequest];

        return mutableRequest;
    }
    
	[ADCustomHeaderHandler applyCustomHeadersTo:mutableRequest];
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
    _connection = nil;
}


@end
