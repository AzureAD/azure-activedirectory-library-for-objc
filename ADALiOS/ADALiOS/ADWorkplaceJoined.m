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

#import "ADWorkplaceJoined.h"
#import "ADAuthenticationSettings.h"
#import "NSString+ADHelperMethods.h"
#import "ADErrorCodes.h"
#import "ADKeyChainHelper.h"
#import "ADALiOS.h"
#import "ADURLProtocol.h"

NSString* const AD_WPJ_LOG = @"Workplace join";

static SecIdentityRef sAD_Identity_Ref;

@implementation ADWorkplaceJoined

//Reads the device identity from the keychain:
+(SecIdentityRef) getIdentityWithError: (ADAuthenticationError *__autoreleasing *) error
{
    NSString* keychainGroup = [ADAuthenticationSettings sharedInstance].clientTLSKeychainGroup;
    ADKeyChainHelper* identityHelper = [[ADKeyChainHelper alloc] initWithClass:(__bridge id)kSecClassIdentity
                                                                       generic:nil
                                                                   sharedGroup:keychainGroup];
    SecIdentityRef identity =
        (SecIdentityRef)[identityHelper getItemTypeRefWithAttributes:@{(__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPrivate}
                                                           error:error];
    return identity;
}

+(BOOL) startWebViewTLSSessionWithError: (ADAuthenticationError *__autoreleasing *) error
{
    @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
    {
        AD_LOG_VERBOSE(AD_WPJ_LOG, @"Attempting to start the client TLS session for webview.");
        
        if (sAD_Identity_Ref)
        {
            AD_LOG_WARN(AD_WPJ_LOG, @"The previous session was not cleared.");
            CFRelease(sAD_Identity_Ref);
            sAD_Identity_Ref = NULL;
        }
        
        SecIdentityRef identity = [self getIdentityWithError:error];
        BOOL succeeded = NO;
        if (identity)//Start the URL loading hook only if certificate is available
        {
            //If we have a certificate to supply over the webview, we use the custom URL protocol
            //hook of Apple's URL loading system to intercept the client TLS challenge and provide
            //the client certificate. Please note that when the class is registered, all HTTPS traffic
            //will go through this class. See ADURLProtocol implementation for more details.
            sAD_Identity_Ref = identity;
            if ([NSURLProtocol registerClass:[ADURLProtocol class]])
            {
                succeeded = YES;
                AD_LOG_VERBOSE(AD_WPJ_LOG, @"Client TLS session started.");
            }
            else
            {
                ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Failed to register NSURLProtocol."];
                if (error)
                {
                    *error = adError;
                }
                sAD_Identity_Ref = NULL;//Cleanup
                CFRelease(identity);
            }
        }
        else
        {
            AD_LOG_VERBOSE(AD_WPJ_LOG, @"No workplace join certificate extracted.");
        }
        return succeeded;
    }
}

/* Stops the HTTPS interception. */
+(void) endWebViewTLSSession
{
    @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
    {
        [NSURLProtocol unregisterClass:[ADURLProtocol class]];
        if (sAD_Identity_Ref)
        {
            CFRelease(sAD_Identity_Ref);
            sAD_Identity_Ref = NULL;
        }
        else
        {
            AD_LOG_WARN(AD_WPJ_LOG, @"Calling endWebViewTLSSession without active session.")
        }
        AD_LOG_VERBOSE(AD_WPJ_LOG, @"Client TLS session ended");
    }
}

+(BOOL) handleClientTLSChallenge:(NSURLAuthenticationChallenge *)challenge
{
    BOOL succeeded = NO;
    if ([challenge.protectionSpace.authenticationMethod caseInsensitiveCompare:NSURLAuthenticationMethodClientCertificate] == NSOrderedSame )
    {
        BOOL ownIdentity = NO;
        SecIdentityRef identity;
        
        @synchronized(self)//Protect the sAD_Identity_Ref from being cleared while used.
        {
            //The static member will be set in the case of web view session, but not in more ad-hock
            //token endpoint requests:
            identity = sAD_Identity_Ref;
            if (!identity)
            {
                //Try to read it from the keychain again:
                identity = [self getIdentityWithError:nil];
                ownIdentity = (identity != NULL);
            }
            
            // This is the client TLS challenge: use the identity to authenticate:
            if (identity)
            {
                AD_LOG_VERBOSE_F(AD_WPJ_LOG, @"Attempting to handle client TLS challenge for host: %@", challenge.protectionSpace.host);
                
                SecCertificateRef clientCertificate = NULL;
                OSStatus          status            = SecIdentityCopyCertificate(identity, &clientCertificate );
                if (errSecSuccess == status)
                {
                    //TODO: Figure out if the sCertificate should be leveraged at all.
                    NSArray* certs = [NSArray arrayWithObjects: (__bridge id)clientCertificate, nil];
                    NSURLCredential* cred = [NSURLCredential credentialWithIdentity:sAD_Identity_Ref
                                                                       certificates:certs
                                                                        persistence:NSURLCredentialPersistenceNone];
                    [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
                    
                    AD_LOG_VERBOSE(AD_WPJ_LOG, @"Client TLS challenge responded.");
                    CFRelease(clientCertificate);
                    
                    succeeded = YES;
                }
                else
                {
                    AD_LOG_WARN_F(AD_WPJ_LOG, @"SecIdentityCopyCertificate failed with error: %ld", (long)status);
                }
            }
            else
            {
                AD_LOG_WARN(AD_WPJ_LOG, @"Cannot respond to client TLS request. Identity is not present.");
            }
        }//@synchronized
        
        if (ownIdentity)
        {
            CFRelease(identity);
        }
    }//Challenge type

    return succeeded;
}

@end
