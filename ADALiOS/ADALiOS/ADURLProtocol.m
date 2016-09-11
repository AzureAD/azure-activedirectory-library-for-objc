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

NSString* const sLog = @"HTTP Protocol";
static NSString* s_endURL = nil;
static NSString* kADURLProtocolPropertyKey = @"ADURLProtocol";

@implementation ADURLProtocol
{
    NSURLConnection *_connection;
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
        if ( [NSURLProtocol propertyForKey:kADURLProtocolPropertyKey inRequest:request] == nil )
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
    
    AD_LOG_VERBOSE_F(sLog, @"startLoading host: %@", [self.request.URL host] );
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];
    [NSURLProtocol setProperty:@"YES" forKey:kADURLProtocolPropertyKey inRequest:mutableRequest];
    _connection = [[NSURLConnection alloc] initWithRequest:mutableRequest
                                                  delegate:self
                                          startImmediately:YES];
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(sLog, @"Stop loading");
    [_connection cancel];
}

#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    AD_LOG_VERBOSE_F(sLog, @"connection:didFaileWithError: %@", error);
    [self.client URLProtocol:self didFailWithError:error];
}

-(void) connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    AD_LOG_VERBOSE_F(sLog, @"connection:willSendRequestForAuthenticationChallenge: %@. Previous challenge failure count: %ld", challenge.protectionSpace.authenticationMethod, (long)challenge.previousFailureCount);
    
    if (![ADNTLMHandler handleNTLMChallenge:challenge urlRequest:[connection currentRequest] customProtocol:self])
    {
        // Do default handling
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

#pragma mark - NSURLConnectionDataDelegate Methods

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse
{
    AD_LOG_VERBOSE_F(sLog, @"HTTPProtocol::connection:willSendRequest:. Redirect response: %@. New request:%@", redirectResponse.URL, request.URL);
    
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
                                                        code:NSURLErrorCannotFindHost
                                                    userInfo:@{ NSURLErrorFailingURLErrorKey : request.URL }];
            [self.client URLProtocol:self didFailWithError:failingError];
        }
        return nil;
    }
    
    NSMutableURLRequest* mutableRequest = [request mutableCopy];
    if(![mutableRequest.allHTTPHeaderFields valueForKey:@"x-ms-PkeyAuth"])
    {
        [mutableRequest addValue:@"1.0" forHTTPHeaderField:@"x-ms-PkeyAuth"];
    }
    
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
