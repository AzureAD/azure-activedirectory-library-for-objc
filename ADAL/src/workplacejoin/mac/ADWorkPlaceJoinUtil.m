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

#import "ADWorkPlaceJoinUtil.h"
#import "ADKeychainUtil.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADRegistrationInformation.h"

// Convenience macro for checking keychain status codes while looking up the WPJ information.
#define CHECK_KEYCHAIN_STATUS(OPERATION) \
{ \
  if (status != noErr) \
  { \
    ADAuthenticationError* adError = [ADAuthenticationError keychainErrorFromOperation:OPERATION status:status correlationId:context.correlationId];\
    if (error) { *error = adError; } \
    goto _error; \
  } \
}

@implementation ADWorkPlaceJoinUtil

+ (ADRegistrationInformation *)getRegistrationInformation:(id<MSIDRequestContext>)context
                                             urlChallenge:(NSURLAuthenticationChallenge *)challenge
                                                    error:(ADAuthenticationError * __autoreleasing *)error
{
    ADRegistrationInformation *info = nil;
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSString *certificateIssuer  = nil;
    OSStatus status = noErr;
    
    MSID_LOG_VERBOSE(context, @"Attempting to get WPJ registration information");
    identity = [self copyWPJIdentity:context issuer:&certificateIssuer certificateAuthorities:challenge.protectionSpace.distinguishedNames];
    
    // If there's no identity in the keychain, return nil. adError won't be set if the
    // identity can't be found since this isn't considered an error condition.
    if (!identity || CFGetTypeID(identity) != SecIdentityGetTypeID())
    {
        MSID_LOG_VERBOSE(context, @"Failed to retrieve WPJ identity.");
        if (identity)
        {
            CFRelease(identity);
            identity = NULL;
        }
        
        return NULL;
    }
    
    // Get the wpj certificate
    MSID_LOG_VERBOSE(context, @"Retrieving WPJ certificate reference.");
    status = SecIdentityCopyCertificate(identity, &certificate);
    CHECK_KEYCHAIN_STATUS(@"Failed to read WPJ certificate.");
    
    certificateSubject = (__bridge_transfer NSString*)(SecCertificateCopySubjectSummary(certificate));
    certificateData = (__bridge_transfer NSData*)(SecCertificateCopyData(certificate));
    
    // Get the private key
    MSID_LOG_VERBOSE(context, @"Retrieving WPJ private key reference.");
    status = SecIdentityCopyPrivateKey(identity, &privateKey);
    CHECK_KEYCHAIN_STATUS(@"Failed to read WPJ private key for identifier.");
    
    if (!certificate || !certificateIssuer || !certificateSubject || !certificateData || !privateKey)
    {
        if (error)
        {
            // The code above will catch missing security items, but not missing item attributes. These are caught here.
            ADAuthenticationError* adError =
            [ADAuthenticationError unexpectedInternalError:@"Missing some piece of WPJ data"
                                             correlationId:context.correlationId];
            
            *error = adError;
        }
        
        goto _error;
    }
    
    // We found all the required WPJ information.
    info = [[ADRegistrationInformation alloc] initWithSecurityIdentity:identity
                                                     certificateIssuer:certificateIssuer
                                                           certificate:certificate
                                                    certificateSubject:certificateSubject
                                                       certificateData:certificateData
                                                            privateKey:privateKey];
    
    // Fall through to clean up resources.
    
_error:
    
    if (identity)
    {
        CFRelease(identity);
        identity = NULL;
    }
    if (certificate)
    {
        CFRelease(certificate);
        certificate = NULL;
    }
    if (privateKey)
    {
        CFRelease(privateKey);
        privateKey = NULL;
    }
    
    return info;
}

+ (SecIdentityRef)copyWPJIdentity:(id<MSIDRequestContext>)context
                           issuer:(NSString **)issuer
           certificateAuthorities:(NSArray<NSData *> *)authorities

{
    if (![authorities count])
    {
        return NULL;
    }
    
    NSDictionary *query = @{ (__bridge id)kSecClass : (__bridge id)kSecClassIdentity,
                             (__bridge id)kSecReturnAttributes:(__bridge id)kCFBooleanTrue,
                             (__bridge id)kSecReturnRef :  (__bridge id)kCFBooleanTrue,
                             (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitAll,
                             (__bridge id)kSecMatchIssuers : authorities
                             };
    
    CFArrayRef identityList = NULL;
    SecIdentityRef identityRef = NULL;
    NSDictionary *identityDict = nil;
    NSData *currentIssuer = nil;
    NSString *currentIssuerName = nil;
    
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&identityList);
    
    if (status != errSecSuccess)
    {
        return NULL;
    }
    
    CFIndex identityCount = CFArrayGetCount(identityList);
    NSString *challengeIssuerName = [[NSString alloc] initWithData:authorities[0] encoding:NSASCIIStringEncoding];
    
    for (int resultIndex = 0; resultIndex < identityCount; resultIndex++)
    {
        identityDict = (NSDictionary *)CFArrayGetValueAtIndex(identityList, resultIndex);
        
        if ([identityDict isKindOfClass:[NSDictionary class]])
        {
            currentIssuer = [identityDict objectForKey:(__bridge NSString*)kSecAttrIssuer];
            currentIssuerName = [[NSString alloc] initWithData:currentIssuer encoding:NSASCIIStringEncoding];
            
            /* The issuer name returned from the certificate in keychain is capitalized but the issuer name returned from the TLS challenge is not.
             Hence we need to do a caseInsenstitive compare to match the issuer.
             */
            if ([challengeIssuerName caseInsensitiveCompare:currentIssuerName] == NSOrderedSame)
            {
                identityRef = (__bridge_retained SecIdentityRef)[identityDict objectForKey:(__bridge NSString*)kSecValueRef];
                
                if (issuer)
                {
                    *issuer = currentIssuerName;
                }
                
                break;
            }
        }
    }
    
    if (identityList)
    {
        CFRelease(identityList);
        identityList = NULL;
    }
    
    return identityRef; //Caller must call CFRelease
}

@end

