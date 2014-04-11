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

#import "HTTPProtocol.h"

@implementation HTTPProtocol
{
    NSURLConnection *_connection;
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    if ( [[request.URL.scheme lowercaseString] isEqualToString:@"https"] )
    {
        if ( [NSURLProtocol propertyForKey:@"HTTPProtocol" inRequest:request] == nil )
        {
            DebugLog( @"YES: %@", [request.URL absoluteString] );

            return YES;
        }
    }
    
    DebugLog( @"NO: %@", [request.URL absoluteString] );
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    DebugLog( @"%@", [request.URL absoluteString] );
    
    return request;
}

- (void)startLoading
{
    DebugLog( @"startLoading" );
    
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];

    [NSURLProtocol setProperty:@"YES" forKey:@"HTTPProtocol" inRequest:mutableRequest];
    
    _connection = [[NSURLConnection alloc] initWithRequest:mutableRequest delegate:self startImmediately:YES];
}

- (void)stopLoading
{
    DebugLog( @"stopLoading" );
}

#pragma mark - Private Methods



#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    DebugLog( @"stopLoading" );
    
    [self.client URLProtocol:self didFailWithError:error];
}

//- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)connection
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    DebugLog( @"%@", challenge.protectionSpace.authenticationMethod );
/*
    if ( [challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodClientCertificate] == NSOrderedSame )
    {
        NSArray* arr = challenge.protectionSpace.distinguishedNames;
        NSString* str = challenge.protectionSpace.host;
        NSString* realm = challenge.protectionSpace.realm;
        // This is the client TLS challenge: Load our PFX/P12 and extract the client certificate
        NSData *certificateData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"TestCert" ofType:@"p12"]];
        
        if ( certificateData )
        {
            SecIdentityRef identity = NULL;
            
            if ( [self extractIdentity:&identity fromPKCS12Data:certificateData] == 0 )
            {
                SecCertificateRef clientCertificate = NULL;
                OSStatus          status            = SecIdentityCopyCertificate( identity, &clientCertificate );
                
                if ( status == 0 )
                {
                    CFMutableArrayRef clientCertificates = CFArrayCreateMutable( NULL, 1, NULL );
                    
                    CFArrayAppendValue( clientCertificates, clientCertificate );
                    
                    [challenge.sender useCredential:[NSURLCredential credentialWithIdentity:identity certificates:(__bridge NSArray *)clientCertificates persistence:NSURLCredentialPersistenceNone] forAuthenticationChallenge:challenge];
                    
                    CFRelease( clientCertificates );
                    CFRelease( clientCertificate );
                    CFRelease( identity );
                    
                    return;
                }
                
                CFRelease( clientCertificate );
                CFRelease( identity );
            }
        }
    }
    
    // Do default handling
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
*/}


// Deprecated authentication delegates.
//- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace;
//- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
//- (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

#pragma mark - NSURLConnectionDataDelegate Methods

//- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)response;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    DebugLog( @"%@", response.MIMEType );
    
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    DebugLog( @"" );
    
    [self.client URLProtocol:self didLoadData:data];
}

//- (NSInputStream *)connection:(NSURLConnection *)connection needNewBodyStream:(NSURLRequest *)request;
//- (void)connection:(NSURLConnection *)connection   didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite;
//- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse;

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    DebugLog( @"connectionDidFinishLoading" );
    
    [self.client URLProtocolDidFinishLoading:self];
}


@end
