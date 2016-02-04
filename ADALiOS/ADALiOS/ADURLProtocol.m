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

#import "ADALiOS.h"
#import "ADURLProtocol.h"
#import "ADLogger.h"
#import "ADNTLMHandler.h"
#import "ADCustomHeaderHandler.h"

static NSString* const sLog = @"HTTP Protocol";
static NSMutableDictionary* s_handlers = nil;


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
            AD_LOG_VERBOSE_F(sLog, @"Requested handling of URL host: %@", [request.URL host]);

            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(sLog, @"Ignoring handling of URL host: %@", [request.URL host]);
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(sLog, @"canonicalRequestForRequest host: %@", [request.URL host] );
    
    return request;
}

- (void)startLoading
{
    if (!self.request)
    {
        AD_LOG_WARN(sLog, @"startLoading called without specifying the request.");
        return;
    }
    
    [self startLoading:self.request.URL];
}

- (void)startLoading:(NSURL*)url
{
    AD_LOG_VERBOSE_F(sLog, @"startLoading host: %@", [url host] );
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];
    [mutableRequest setURL:url];
    [NSURLProtocol setProperty:@"YES" forKey:@"ADURLProtocol" inRequest:mutableRequest];
    _connection = [[NSURLConnection alloc] initWithRequest:mutableRequest
                                                  delegate:self
                                          startImmediately:YES];
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(sLog, @"Stop loading");
    [_connection cancel];
    [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil]];
}

#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    AD_LOG_VERBOSE_F(sLog, @"connection:didFaileWithError: %@", error);
    [self.client URLProtocol:self didFailWithError:error];
}

- (void)connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSString* authMethod = [challenge.protectionSpace.authenticationMethod lowercaseString];
    
    AD_LOG_VERBOSE_F(sLog, @"connection:willSendRequestForAuthenticationChallenge: %@. Previous challenge failure count: %ld", authMethod, (long)challenge.previousFailureCount);
    
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
    AD_LOG_VERBOSE_F(sLog, @"HTTPProtocol::connection:willSendRequest:. Redirect response: %@. New request:%@", response.URL, request.URL);
    //Ensure that the webview gets the redirect notifications:
    NSMutableURLRequest* mutableRequest = [request mutableCopy];
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
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [self.client URLProtocol:self didLoadData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    [self.client URLProtocolDidFinishLoading:self];
    _connection = nil;
}


@end
