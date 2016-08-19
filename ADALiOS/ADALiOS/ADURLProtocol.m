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

#import "ADALiOS.h"
#import "ADURLProtocol.h"
#import "ADLogger.h"
#import "ADNTLMHandler.h"
#import "ADCustomHeaderHandler.h"

static NSMutableDictionary* s_handlers = nil;
static NSString* s_endURL = nil;

static NSString* kADURLProtocolPropertyKey = @"ADURLProtocol";

@implementation ADURLProtocol
{
    NSURLConnection *_connection;
}

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
    }
    return [NSURLProtocol registerClass:self];
}

+ (void)unregisterProtocol
{
    [NSURLProtocol unregisterClass:self];
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
        
        AD_LOG_VERBOSE_F(@"+[ADURLProtocol canInitWithRequest:] handling host", @"host: %@", [request.URL host]);
        //This class needs to handle only TLS. The check below is needed to avoid infinite recursion between starting and checking
        //for initialization
        if (![NSURLProtocol propertyForKey:@"ADURLProtocol" inRequest:request])
        {
            
            
            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(@"+[ADURLProtocol canInitWithRequest:] ignoring handling of host",@"host: %@", [request.URL host]);
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(@"+[ADURLProtocol canonicalRequestForRequest:]", @"host: %@", [request.URL host] );
    
    return request;
}

- (void)startLoading
{
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol startLoading]", @"host: %@", [self.request.URL host]);
    
    NSMutableURLRequest* request = [self.request mutableCopy];
    
    [NSURLProtocol setProperty:@YES forKey:kADURLProtocolPropertyKey inRequest:request];
    
    _connection = [[NSURLConnection alloc] initWithRequest:request
                                                  delegate:self
                                          startImmediately:YES];
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol stopLoading]", @"host: %@", [self.request.URL host]);
    
    [_connection cancel];
    _connection = nil;
}

#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    (void)connection;
    
    AD_LOG_ERROR_F(@"-[ADURLProtocol connection:didFailedWithError:]", error.code, @"error: %@", error);
    [self.client URLProtocol:self didFailWithError:error];
}

- (void)connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSString* authMethod = [challenge.protectionSpace.authenticationMethod lowercaseString];
    
    AD_LOG_VERBOSE_F(@"connection:willSendRequestForAuthenticationChallenge:", @"%@. Previous challenge failure count: %ld", authMethod, (long)challenge.previousFailureCount);
    
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

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse
{
    (void)connection;
    
    AD_LOG_VERBOSE_F(@"-[ADURLProtocol connection:willSendRequest:]",  @"Redirect response: %@. New request:%@", redirectResponse.URL, request.URL);
    
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
    
    if (redirectResponse)
    {
        // If we're being redirected by the server that will create a whole new connection that we still need to observe
        [NSURLProtocol removePropertyForKey:kADURLProtocolPropertyKey inRequest:mutableRequest];
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
}


@end
