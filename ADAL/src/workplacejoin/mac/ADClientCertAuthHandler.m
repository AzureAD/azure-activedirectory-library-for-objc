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
#import "ADWebAuthController+Internal.h"
#import "ADAuthenticationViewController.h"

@interface ADCertificateChooserHelper : NSObject 

+ (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                    host:(NSString *)host
                           correlationId:(NSUUID *)correlationId;

@end


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
        NSString *distinguishedNameString = [[[NSString alloc] initWithData:distinguishedName encoding:NSASCIIStringEncoding] lowercaseString];
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
    ADRegistrationInformation *info = [ADWorkPlaceJoinUtil getRegistrationInformation:protocol.context urlChallenge:challenge error:&adError];
    if (!info || ![info isWorkPlaceJoined])
    {
        MSID_LOG_INFO(protocol.context, @"Device is not workplace joined");
        MSID_LOG_INFO_PII(protocol.context, @"Device is not workplace joined. host: %@", challenge.protectionSpace.host);
        
        // In other cert auth cases we send Cancel to ensure that we continue to get
        // auth challenges, however when we do that with WPJ we don't get the subsequent
        // enroll dialog *after* the failed clientTLS challenge.
        //
        // Using DefaultHandling will result in the OS not handing back client TLS
        // challenges for another ~60 seconds, behavior that looks broken in the
        // user CBA case, but here is masked by the user having to enroll their
        // device.
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return YES;
    }
    
    MSID_LOG_INFO(protocol.context, @"Responding to WPJ cert challenge");
    MSID_LOG_INFO_PII(protocol.context, @"Responding to WPJ cert challenge. host: %@", challenge.protectionSpace.host);
    
    NSURLCredential *creds = [NSURLCredential credentialWithIdentity:info.securityIdentity
                                                        certificates:@[(__bridge id)info.certificate]
                                                         persistence:NSURLCredentialPersistenceNone];
    
    completionHandler(NSURLSessionAuthChallengeUseCredential, creds);
    
    return YES;
}

+ (SecIdentityRef)promptUserForIdentity:(NSArray *)issuers
                                   host:(NSString *)host
                          correlationId:(NSUUID *)correlationId
{
    NSMutableDictionary *query =
    [@{
      (id)kSecClass : (id)kSecClassIdentity,
      (id)kSecMatchLimit : (id)kSecMatchLimitAll,
      } mutableCopy];
    
    if (issuers.count > 0)
    {
        [query setObject:issuers forKey:(id)kSecMatchIssuers];
    }
    
    CFTypeRef result = NULL;
    
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, &result);
    if (status == errSecItemNotFound)
    {
        MSID_LOG_INFO_CORR(correlationId, @"No certificate found matching challenge");
        return nil;
    }
    else if (status != errSecSuccess)
    {
        MSID_LOG_ERROR_CORR(correlationId, @"Failed to find identity matching issuers with %d error.", status);
        return nil;
    }
    
    return [ADCertificateChooserHelper showCertSelectionSheet:(__bridge NSArray *)result host:host correlationId:correlationId];
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
    
    MSID_LOG_INFO(protocol.context, @"Attempting to handle client certificate challenge");
    MSID_LOG_INFO_PII(protocol.context, @"Attempting to handle client certificate challenge. host: %@", host);
    
    // See if this is a challenge for the WPJ cert.
    NSArray<NSData*> *distinguishedNames = challenge.protectionSpace.distinguishedNames;
    if ([self isWPJChallenge:distinguishedNames])
    {
        return [self handleWPJChallenge:challenge protocol:protocol completionHandler:completionHandler];
    }
    
    // Otherwise check if a preferred identity is set for this host
    SecIdentityRef identity = SecIdentityCopyPreferred((CFStringRef)host, NULL, (CFArrayRef)distinguishedNames);
    
    if (!identity)
    {
        // If there was no identity matched for the exact host, try to match by URL
        // URL matching is more flexible, as it's doing a wildcard matching for different subdomains
        // However, we need to do both, because if there's an entry by hostname, matching by URL won't find it
        identity = SecIdentityCopyPreferred((CFStringRef)task.currentRequest.URL.absoluteString, NULL, (CFArrayRef)distinguishedNames);
    }
    
    if (identity != NULL)
    {
        MSID_LOG_INFO(protocol.context, @"Using preferred identity");
    }
    else
    {
        // If not prompt the user to select an identity
        identity = [self promptUserForIdentity:distinguishedNames host:host correlationId:correlationId];
        if (identity == NULL)
        {
            MSID_LOG_INFO(protocol.context, @"No identity returned from cert chooser");
            
            // If no identity comes back then we can't handle the request
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
            return YES;
        }
        
        // Adding a retain count to match the retain count from SecIdentityCopyPreferred
        CFRetain(identity);
        MSID_LOG_INFO(protocol.context, @"Using user selected certificate");
    }

    
    MSID_LOG_INFO(protocol.context, @"Responding to cert auth challenge with certicate");
    
    /*
     The `certificates` parameter accepts an array of /intermediate/ certificates leading from the leaf to the root.  It must not include the leaf certificate because the system gets that from the digital identity.  It should not include a root certificate because, when the server does trust evaluation on the leaf, it already has a copy of the relevant root. Therefore, we are sending "nil" to the certificates array.
     */
    NSURLCredential *credential = [[NSURLCredential alloc] initWithIdentity:identity certificates:nil persistence:NSURLCredentialPersistenceNone];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
    CFRelease(identity);
    return YES;
}

@end

@implementation ADCertificateChooserHelper
{
    NSUUID *_correlationId;
    NSWindow *_window;
    SFChooseIdentityPanel *_panel;
    dispatch_semaphore_t _sem;
    NSInteger _returnCode;
}

+ (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                    host:(NSString *)host
                           correlationId:(NSUUID *)correlationId
{
    NSString *localizedTemplate = NSLocalizedString(@"Please select a certificate for %1", @"certificate dialog selection prompt \"%1\" will be replaced with the URL host");
    NSString *message = [localizedTemplate stringByReplacingOccurrencesOfString:@"%1" withString:host];
    
    ADCertificateChooserHelper *helper = [ADCertificateChooserHelper new];
    helper->_correlationId = correlationId;
    return [helper showCertSelectionSheet:identities message:message];
}

- (void)beginSheet:(NSArray *)identities
           message:(NSString *)message
{
    _window = [[[ADWebAuthController sharedInstance] viewController] webviewWindow];
    _panel = [SFChooseIdentityPanel new];
    [_panel setAlternateButtonTitle:NSLocalizedString(@"Cancel", "Cancel button on cert selection sheet")];
    [_panel beginSheetForWindow:_window
                  modalDelegate:self
                 didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)
                    contextInfo:NULL
                     identities:identities
                        message:message];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(webAuthDidFail:) name:ADWebAuthDidFailNotification object:nil];
}

- (SecIdentityRef)showCertSelectionSheet:(NSArray *)identities
                                 message:(NSString *)message
{
    _sem = dispatch_semaphore_create(0);
    MSID_LOG_INFO_CORR(_correlationId, @"Displaying Cert Selection Sheet");
    
    // This code should always be called from a network thread.
    assert(![NSThread isMainThread]);
    
    dispatch_async(dispatch_get_main_queue(), ^{ [self beginSheet:identities message:message]; });
    dispatch_semaphore_wait(_sem, DISPATCH_TIME_FOREVER);
    
    if (_returnCode != NSModalResponseOK)
    {
        MSID_LOG_INFO_CORR(_correlationId, @"no certificate selected");
        return NULL;
    }
    
    SecIdentityRef identity = _panel.identity;
    return identity;
}

- (void)sheetDidEnd:(NSWindow *)window
         returnCode:(NSInteger)returnCode
        contextInfo:(void *)contextInfo
{
    (void)window;
    (void)contextInfo;
    
    _returnCode = returnCode;
    _window = nil;
    [[NSNotificationCenter defaultCenter] removeObserver:self name:ADWebAuthDidFailNotification object:nil];
    dispatch_semaphore_signal(_sem);
}

- (void)webAuthDidFail:(NSNotification *)aNotification
{
    (void)aNotification;
    
    if (!_panel || !_window)
    {
        return;
    }
    
    // If web auth fails while the sheet is up that usually means the connection timed out, tear
    // down the cert selection sheet.
    
    MSID_LOG_INFO_CORR(_correlationId, @"Aborting cert selection due to web auth failure");
    NSArray *sheets = _window.sheets;
    if (sheets.count < 1)
    {
        MSID_LOG_ERROR_CORR(_correlationId, @"Unable to find sheet to dismiss for client cert auth handler.");
        return;
    }
    // It turns out the SFChooseIdentityPanel is not the real sheet that gets displayed, so telling the window to end it
    // results in nothing happening. If I instead pull out the sheet from the window itself I can tell the window to end
    // that and it works.
    [_window endSheet:sheets[0] returnCode:NSModalResponseCancel];
}

@end
