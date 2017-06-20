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

#import <Security/Security.h>
#import <SecurityInterface/SFChooseIdentityPanel.h>

#import "ADClientCertAuthHandler.h"
#import "ADWorkPlaceJoinUtil.h"
#import "ADRegistrationInformation.h"
#import "ADWorkPlaceJoinConstants.h"


@implementation ADClientCertAuthHandler

+ (void)load
{
    [ADURLProtocol registerHandler:self authMethod:NSURLAuthenticationMethodClientCertificate];
}

+ (void)resetHandler
{
}


+ (BOOL)isWPJChallenge:(NSArray *)distinguishedNames
{
    
    for (NSData *distinguishedName in distinguishedNames)
    {
        NSString *distinguishedNameString = [[[NSString alloc] initWithData:distinguishedName encoding:NSISOLatin1StringEncoding] lowercaseString];
        if ([distinguishedNameString containsString:[kADALProtectionSpaceDistinguishedName lowercaseString]])
        {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)handleWPJChallenge:(NSURLAuthenticationChallenge *)challenge
                  protocol:(ADURLProtocol *)protocol
         completionHandler:(ChallengeCompletionHandler)completionHandler
{
    ADAuthenticationError *adError = nil;
    ADRegistrationInformation *info = [ADWorkPlaceJoinUtil getRegistrationInformation:protocol.context error:&adError];
    if (!info || ![info isWorkPlaceJoined])
    {
        AD_LOG_INFO_F(@"Device is not workplace joined.", protocol.context.correlationId, @"host: %@", challenge.protectionSpace.host);
        return NO;
    }
    
    AD_LOG_INFO_F(@"Responding to WPJ cert challenge", protocol.context.correlationId, @"host: %@", challenge.protectionSpace.host);
    
    NSURLCredential *creds = [NSURLCredential credentialWithIdentity:info.securityIdentity
                                                        certificates:@[(__bridge id)info.certificate]
                                                         persistence:NSURLCredentialPersistenceNone];
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, creds);
    
    return YES;
}

+ (SecIdentityRef)showCertSelectionDialog:(NSArray *)identities
                                     host:(NSString *)host
                            correlationId:(NSUUID *)correlationId
{
    SFChooseIdentityPanel *panel = [SFChooseIdentityPanel sharedChooseIdentityPanel];
    
    NSString *localizedTemplate = NSLocalizedString(@"Please select a certificate for %1", @"certificate dialog selection prompt \"%1\" will be replaced with the URL host");
    NSString *message = [localizedTemplate stringByReplacingOccurrencesOfString:@"%1" withString:host];
    
    NSInteger result = [panel runModalForIdentities:identities message:message];
    if (result == NSModalResponseCancel)
    {
        AD_LOG_INFO(@"User canceled cert selection dialog", correlationId, nil);
        return NULL;
    }
    
    return panel.identity;
}

+ (SecIdentityRef)promptUserForIdentity:(NSArray *)issuers
                                   host:(NSString *)host
                          correlationId:(NSUUID *)correlationId
{
    NSDictionary *query =
    @{
      (id)kSecClass : (id)kSecClassIdentity,
      (id)kSecMatchIssuers : issuers,
      (id)kSecMatchLimit : (id)kSecMatchLimitAll,
      };
    
    CFTypeRef result = NULL;
    
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound)
    {
        AD_LOG_INFO(@"No certificate found matching challenge", correlationId, nil);
        return nil;
    }
    else if (status != errSecSuccess)
    {
        AD_LOG_ERROR(([NSString stringWithFormat:@"Failed to find identity matching issuers with %d error.", status]), status, correlationId, nil);
        return nil;
    }
    
    if (![NSThread isMainThread])
    {
        __block dispatch_semaphore_t dsem = dispatch_semaphore_create(0);
        __block SecIdentityRef certResult = NULL;
        dispatch_async(dispatch_get_main_queue(), ^{
            certResult = [self showCertSelectionDialog:(__bridge NSArray *)result host:host correlationId:correlationId];
            CFRetain(certResult);
            dispatch_semaphore_signal(dsem);
        });
        
        dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
        CFAutorelease(certResult);
        return certResult;
    }
    else
    {
        return [self showCertSelectionDialog:(__bridge NSArray *)result host:host correlationId:correlationId];
    }
}


+ (BOOL)handleChallenge:(NSURLAuthenticationChallenge *)challenge
                session:(NSURLSession *)session
                   task:(NSURLSessionTask *)task
               protocol:(ADURLProtocol *)protocol
      completionHandler:(ChallengeCompletionHandler)completionHandler;
{
#pragma unused(session)
#pragma unused(task)
    
    NSUUID *correlationId = protocol.context.correlationId;
    NSString *host = challenge.protectionSpace.host;
    AD_LOG_INFO_F(@"Attempting to handle client certificate challenge", correlationId, @"host: %@", host);
    
    // See if this is a challenge for the WPJ cert.
    NSArray<NSData*> *distinguishedNames = challenge.protectionSpace.distinguishedNames;
    if ([self isWPJChallenge:distinguishedNames])
    {
        return [self handleWPJChallenge:challenge protocol:protocol completionHandler:completionHandler];
    }
    
    // Otherwise check if a preferred identity is set for this host
    SecIdentityRef identity = SecIdentityCopyPreferred((CFStringRef)host, NULL, (CFArrayRef)distinguishedNames);
    if (identity != NULL)
    {
        AD_LOG_INFO(@"Using preferred identity", correlationId, nil);
    }
    else
    {
        // If not prompt the user to select an identity
        identity = [self promptUserForIdentity:distinguishedNames host:host correlationId:correlationId];
        if (identity == NULL)
        {
            // If no identity comes back then we can't handle the request
            return NO;
        }
        
        CFRetain(identity);
        AD_LOG_INFO(@"Using user selected certificate", correlationId, nil);
    }
    
    SecCertificateRef cert = NULL;
    OSStatus status = SecIdentityCopyCertificate(identity, &cert);
    if (status != errSecSuccess)
    {
        CFRelease(identity);
        AD_LOG_ERROR(@"Failed to copy certificate from identity", AD_ERROR_UNEXPECTED, correlationId, nil);
        return NO;
    }
    
    AD_LOG_INFO(@"Responding to cert auth challenge with certicate", correlationId, nil);
    NSURLCredential *credential = [[NSURLCredential alloc] initWithIdentity:identity certificates:@[(__bridge id)cert] persistence:NSURLCredentialPersistenceForSession];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    CFRelease(cert);
    CFRelease(identity);
    return YES;
}
    


@end
