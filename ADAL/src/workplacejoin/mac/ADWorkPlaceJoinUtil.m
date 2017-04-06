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
#import "ADLogger+Internal.h"
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

+ (ADRegistrationInformation *)getRegistrationInformation:(id<ADRequestContext>)context
                                                    error:(ADAuthenticationError * __autoreleasing *)error
{
    ADRegistrationInformation *info = nil;
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSString *certificateIssuer  = nil;
    ADAuthenticationError *adError = nil;
    
    if (error)
    {
        *error = nil;
    }
    
    AD_LOG_VERBOSE(@"Attempting to get WPJ registration information", context.correlationId, nil);
    
    [self copyCertificate:&certificate identity:&identity issuer:&certificateIssuer context:context error:&adError];
    if (adError)
    {
        if (error)
        {
            *error = adError;
        }
        AD_LOG_ERROR_F(@"Failed to retrieve WPJ certificate and identify - ", adError.code, nil, @"%@ correlation id.", context.correlationId);
        goto _error;
    }
    
    // If there's no certificate in the keychain, return nil. adError won't be set if the
    // cert can't be found since this isn't considered an error condition.
    if (!certificate)
    {
        return nil;
    }
    
    certificateSubject = (__bridge_transfer NSString*)(SecCertificateCopySubjectSummary(certificate));
    certificateData = (__bridge_transfer NSData*)(SecCertificateCopyData(certificate));
    
    // Get the private key
    AD_LOG_VERBOSE(@"Retrieving WPJ private key reference", context.correlationId, nil);
    
    privateKey = [self copyPrivateKeyRefForIdentifier:privateKeyIdentifier context:context error:&adError];
    if (adError)
    {
        if (error)
        {
            *error = adError;
        }
        AD_LOG_ERROR_F(@"Failed to retrieve WPJ private key reference - ", adError.code, nil, @"%@ correlation id.", context.correlationId);
        goto _error;
    }
    
    
    if (!identity || !certificateIssuer || !certificateSubject || !certificateData || !privateKey)
    {
        // The code above will catch missing security items, but not missing item attributes. These are caught here.
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Missing some piece of WPJ data" correlationId:context.correlationId];
        if (error)
        {
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
    }
    if (certificate)
    {
        CFRelease(certificate);
    }
    if (privateKey)
    {
        CFRelease(privateKey);
    }
    
    return info;
}


+ (void)copyCertificate:(SecCertificateRef __nullable * __nonnull)certificate
               identity:(SecIdentityRef __nullable * __nonnull)identity
                 issuer:(NSString * __nullable * __nonnull)issuer
                context:(id<ADRequestContext>)context
                error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    OSStatus status = noErr;
    ADAuthenticationError *adError = nil;
    NSData *issuerData = nil;
    NSDictionary *identityQuery = nil;
    CFDictionaryRef result = NULL;
    
    *identity = nil;
    *certificate = nil;
    if (error)
    {
        *error = nil;
    }
    
    *certificate = [self copyWPJCertificateRef:context error:&adError];
    
    if (adError)
    {
        if (error)
        {
            *error = adError;
        }
        
        AD_LOG_ERROR_F(@"Failed to retrieve WPJ client certificate from keychain - ", adError.code, nil, @"%@ correlation id.", context.correlationId);
        goto _error;
    }
    
    // If there's no certificate in the keychain, adError won't be set since this isn't an error condition.
    if (!*certificate)
    {
        return;
    }
    
    // In OS X the shared access group cannot be set, so the search needs to be more
    // specific. The code below searches the identity by passing the WPJ cert as reference.
    identityQuery = @{ (__bridge id)kSecClass : (__bridge id)kSecClassIdentity,
                       (__bridge id)kSecReturnRef : (__bridge id)kCFBooleanTrue,
                       (__bridge id)kSecReturnAttributes : (__bridge id)kCFBooleanTrue,
                       (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
                       (__bridge id)kSecValueRef : (__bridge id)*certificate
                       };
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityQuery, (CFTypeRef*)&result);
    CHECK_KEYCHAIN_STATUS(@"Failed to retrieve WPJ identity from keychain.");
    
    issuerData = [(__bridge NSDictionary*)result objectForKey:(__bridge id)kSecAttrIssuer];
    if (issuerData)
    {
        *issuer = [[NSString alloc] initWithData:issuerData encoding:NSISOLatin1StringEncoding];
    }
    
    *identity = (__bridge SecIdentityRef)([(__bridge NSDictionary*)result objectForKey:(__bridge id)kSecValueRef]);
    if (*identity)
    {
        CFRetain(*identity);
    }
    
    CFRelease(result);
    
    return;
    
_error:
    
    if (*identity)
    {
        CFRelease(*identity);
    }
    *identity = nil;
    
    if (*certificate)
    {
        CFRelease(*certificate);
    }
    *certificate = nil;
    
    *issuer = nil;
}


+ (SecCertificateRef)copyWPJCertificateRef:(id<ADRequestContext>)context
                                     error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    OSStatus status= noErr;
    SecCertificateRef certRef = NULL;
    NSData *issuerTag = [self wpjCertIssuerTag];
    
    // Set the private key query dictionary.
    NSDictionary *queryCert = @{ (__bridge id)kSecClass : (__bridge id)kSecClassCertificate,
                                 (__bridge id)kSecAttrLabel : issuerTag
                                 };
    
    // Get the certificate. If the certificate is not found, this is not considered an error.
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryCert, (CFTypeRef*)&certRef);
    if (status == errSecItemNotFound)
    {
        return NULL;
    }
    
    CHECK_KEYCHAIN_STATUS(@"Failed to read WPJ certificate.");
    
    return certRef;
    
_error:
    return NULL;
}

+ (NSData *)wpjCertIssuerTag
{
    return [NSData dataWithBytes:certificateIdentifier length:strlen((const char *)certificateIdentifier)];
}

+ (SecKeyRef)copyPrivateKeyRefForIdentifier:(NSString *)identifier
                                    context:(id<ADRequestContext>)context
                                      error:(ADAuthenticationError* __nullable __autoreleasing * __nullable)error
{
    OSStatus status= noErr;
    SecKeyRef privateKeyReference = NULL;
    
    NSData *privateKeyTag = [NSData dataWithBytes:[identifier UTF8String] length:identifier.length];
    
    // Set the private key query dictionary.
    NSDictionary *privateKeyQuery = @{ (__bridge id)kSecClass : (__bridge id)kSecClassKey,
                                       (__bridge id)kSecAttrApplicationTag : privateKeyTag,
                                       (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
                                       (__bridge id)kSecReturnRef : (__bridge id)kCFBooleanTrue
                                       };
    
    // Get the key.
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKeyQuery, (CFTypeRef*)&privateKeyReference);
    CHECK_KEYCHAIN_STATUS(@"Failed to read WPJ private key for identifier.");
    
    return privateKeyReference;
    
_error:
    return nil;
}

@end

