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
#import "ADLogger.h"

static SecIdentityRef sIdentity;
static SecCertificateRef sCertificate;

NSString* const sLog = @"HTTP Protocol";

@implementation HTTPProtocol
{
    NSURLConnection *_connection;
}

+(void) setIdentity:(SecIdentityRef)identity
{
    if (identity)
    {
        AD_LOG_INFO(sLog, @"Identity set.");
        CFRetain(identity);
        sIdentity = identity;
    }
    else
    {
        AD_LOG_WARN(sLog, @"HTTPProtocol::setIdentity called with NULL parameter");
    }
}

+(void) clearIdentity
{
    if (sIdentity)
    {
        CFRelease(sIdentity);
        sIdentity = NULL;
    }
}

/* Sets the certificate to be used for the client TLS authentication (required with workplace join). */
+(void) setCertificate:(SecCertificateRef) certificate
{
    if (certificate)
    {
        CFRetain(certificate);
        sCertificate = certificate;
    }
    else
    {
        AD_LOG_WARN(sLog, @"HTTPProtocol::setCertificate called with NULL parameter");
    }
};

/* Releases the identity data. Typically called at the end of the client TLS session. */
+(void) clearCertificate
{
    if (sCertificate)
    {
        CFRelease(sCertificate);
        sCertificate = NULL;
    }
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
    if ( [[request.URL.scheme lowercaseString] isEqualToString:@"https"] )
    {
        //This class needs to handle only TLS. The check below is needed to avoid infinite recursion between starting and checking
        //for initialization
        if ( [NSURLProtocol propertyForKey:@"HTTPProtocol" inRequest:request] == nil )
        {
            AD_LOG_VERBOSE_F(sLog, @"Requested handling of URL: %@", [request.URL absoluteString]);

            return YES;
        }
    }
    
    AD_LOG_VERBOSE_F(sLog, @"Ignoring handling of URL: %@", [request.URL absoluteString]);
    
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    AD_LOG_VERBOSE_F(sLog, @"canonicalRequestForRequest: %@", [request.URL absoluteString] );
    
    return request;
}

- (void)startLoading
{
    if (!self.request)
    {
        AD_LOG_WARN(sLog, @"startLoading called without specifying the request.");
        return;
    }
    
    AD_LOG_VERBOSE_F(sLog, @"startLoading: %@", [self.request.URL absoluteString] );
    
    NSMutableURLRequest *mutableRequest = [self.request mutableCopy];

    [NSURLProtocol setProperty:@"YES" forKey:@"HTTPProtocol" inRequest:mutableRequest];
    
    _connection = [[NSURLConnection alloc] initWithRequest:mutableRequest
                                                  delegate:self
                                          startImmediately:YES];
}

- (void)stopLoading
{
    AD_LOG_VERBOSE_F(sLog, @"Stop loading");
    [_connection cancel];
}

#pragma mark - Private Methods



#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    AD_LOG_VERBOSE_F(sLog, @"connection:didFaileWithError: %@", error);
    
    [self.client URLProtocol:self didFailWithError:error];
}

//- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)connection
//- (void) connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
-(void) connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    AD_LOG_VERBOSE_F(sLog, @"connection:willSendRequestForAuthenticationChallenge: %@. Previous challenge failure count: %ld", challenge.protectionSpace.authenticationMethod, (long)challenge.previousFailureCount);

    if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodClientCertificate] == NSOrderedSame )
    {
        // This is the client TLS challenge: use the identity to authenticate:
        if (sIdentity && sCertificate)
        {
            AD_LOG_VERBOSE_F(sLog, @"Attempting to handle client TLS challenge for host: %@", challenge.protectionSpace.host);
            
            SecCertificateRef clientCertificate = NULL;
            OSStatus          status            = SecIdentityCopyCertificate( sIdentity, &clientCertificate );
            if (errSecSuccess == status)
            {
                //TODO: Figure out if the sCertificate should be leveraged at all.
                NSArray* certs = [NSArray arrayWithObjects: (__bridge id)clientCertificate /*, (__bridge id)sCertificate*/, nil];
                NSURLCredential* cred = [NSURLCredential credentialWithIdentity:sIdentity
                                                                   certificates:certs
                                                                    persistence:NSURLCredentialPersistenceNone];
                [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
                
                AD_LOG_VERBOSE(sLog, @"Client TLS challenge responded.");
                CFRelease(clientCertificate);
                return;
            }
            else
            {
                AD_LOG_WARN_F(sLog, @"SecIdentityCopyCertificate failed with error: %ld", (long)status);
            }
        }
        else
        {
            AD_LOG_WARN(sLog, @"Cannot respond to client TLS request. Identity is not set.");
        }
    }
    else if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodServerTrust] == NSOrderedSame)
    {
        //TODO: Figure out if this is even needed:
//        CFArrayRef certs = CFArrayCreate(kCFAllocatorDefault, (const void **) &sCertificate, 1, NULL);
//        SecPolicyRef policy = SecPolicyCreateBasicX509();
//        SecTrustRef trust;
//        
//        OSStatus res = SecTrustCreateWithCertificates(certs, policy, &trust);
//        SecTrustResultType trustResult;
//        res = SecTrustEvaluate(trust, &trustResult);
//        
//        NSURLCredential* cred = [NSURLCredential credentialForTrust:trust];
//        CFRelease(certs);
//        
//        
//        [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
    }
    
    // Do default handling
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    //[challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
}


// Deprecated authentication delegates.
//- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
//- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
//- (void)connection:(NSURLConnection *)connection didCancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

#pragma mark - NSURLConnectionDataDelegate Methods

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)response
{
    AD_LOG_VERBOSE_F(sLog, @"HTTPProtocol::connection:willSendRequest:. Redirect response: %@. New request:%@", response.URL, request.URL);
    //Ensure that the webview gets the redirect notifications:
    if (response)
    {
        NSMutableURLRequest* mutableRequest = [request mutableCopy];
        
        [[self class] removePropertyForKey:@"HTTPProtocol" inRequest:mutableRequest];
        [self.client URLProtocol:self wasRedirectedToRequest:mutableRequest redirectResponse:response];
        
        [_connection cancel];
        [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil]];
        
        return mutableRequest;
    }
    return request;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [self.client URLProtocol:self didLoadData:data];
}

//- (NSInputStream *)connection:(NSURLConnection *)connection needNewBodyStream:(NSURLRequest *)request;
//- (void)connection:(NSURLConnection *)connection   didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite;
//- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse;

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    [self.client URLProtocolDidFinishLoading:self];
    _connection = nil;
}


@end
