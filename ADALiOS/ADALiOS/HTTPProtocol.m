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
        //This class needs to handle only TLS.
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
}

#pragma mark - Private Methods



#pragma mark - NSURLConnectionDelegate Methods

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    AD_LOG_VERBOSE_F(sLog, @"connection:didFaileWithError: %@", error);
    
    [self.client URLProtocol:self didFailWithError:error];
}

//- (BOOL)connectionShouldUseCredentialStorage:(NSURLConnection *)connection
- (void)connection:(NSURLConnection *)connection
willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    AD_LOG_VERBOSE_F(sLog, @"connection:willSendRequestForAuthenticationChallenge: %@", challenge.protectionSpace.authenticationMethod);

    if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodClientCertificate] == NSOrderedSame )
    {
        // This is the client TLS challenge: use the identity to authenticate:
        if ( sIdentity && sCertificate)
        {
            AD_LOG_VERBOSE(sLog, @"Attempting to handle client TLS challenge...");
            SecCertificateRef cert = NULL;
            id certId = (__bridge_transfer id)sCertificate;
            NSArray* certs = [NSArray arrayWithObjects:certId, nil];
            NSURLCredential* cred = [NSURLCredential credentialWithIdentity:sIdentity
                                                               certificates:certs
                                                                persistence:NSURLCredentialPersistenceNone];
            [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
            AD_LOG_VERBOSE(sLog, @"Client TLS challenge responded.");
            }
        else
        {
            AD_LOG_WARN(sLog, @"Cannot respond to client TLS request. Identity is not set.");
        }
    }
    
    // Do default handling
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}


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
