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
#import "ADRegistrationInformation.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADErrorCodes.h"
#import "ADAL_Internal.h"

@implementation ADWorkPlaceJoinUtil

// Convenience macro for checking keychain status codes while looking up the WPJ
// information. We don't send errors for errSecItemNotFound (because not having
// WPJ information is an expected case) or errSecNoAccessForItem (because non-
// Microsoft apps will not be able to access the workplace join information).
#define CHECK_KEYCHAIN_STATUS(_operation) \
{ \
    if (status != noErr) \
    { \
        if (!(status == errSecItemNotFound || status == -25243)) \
        { \
            ADAuthenticationError* adError = \
            [ADAuthenticationError keychainErrorFromOperation:_operation \
                                                       status:status \
                                                correlationId:context.correlationId];\
            if (error) { *error = adError; } \
        } \
        goto _error; \
    } \
}


+ (ADRegistrationInformation *)getRegistrationInformation:(id<MSIDRequestContext>)context
                                                challenge:(NSURLAuthenticationChallenge *)challenge
                                                    error:(ADAuthenticationError * __autoreleasing *)error;
{
    NSString* teamId = [ADKeychainUtil keychainTeamId:error];

#if TARGET_OS_SIMULATOR
    NSString* sharedAccessGroup = nil;
    
    // Only in the simulator if we don't have a shared access group we want the rest of the code to
    // at least attempt to work.
    if (teamId)
    {
        sharedAccessGroup = [NSString stringWithFormat:@"%@.com.microsoft.workplacejoin", teamId];
    }
#else
    if (!teamId)
    {
        return nil;
    }
    NSString* sharedAccessGroup = [NSString stringWithFormat:@"%@.com.microsoft.workplacejoin", teamId];
#endif
    
    MSID_LOG_VERBOSE(nil, @"Attempting to get registration information - shared access Group");
    MSID_LOG_VERBOSE_PII(nil, @"Attempting to get registration information - %@ shared access Group", sharedAccessGroup);
    
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSString *certificateIssuer = nil;
    NSData *issuer = nil;
    NSDictionary *  cerDict = nil;
    
    NSMutableDictionary *identityAttr = [[NSMutableDictionary alloc] init];
    [identityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    [identityAttr setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
#if TARGET_OS_SIMULATOR
    if (sharedAccessGroup)
#endif
    [identityAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    
    CFDictionaryRef result = NULL;
    OSStatus status = noErr;
    //get the issuer information
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef *)&result);
    CHECK_KEYCHAIN_STATUS(@"retrieve wpj identity attr");
            
    cerDict = (__bridge NSDictionary *) result;
    assert([cerDict isKindOfClass:[NSDictionary class]]);
    issuer = [cerDict objectForKey:(__bridge id)kSecAttrIssuer];
    certificateIssuer = [[NSString alloc] initWithData:issuer encoding:NSISOLatin1StringEncoding];
    CFRelease(result);
    result = NULL;
    
    // now get the identity out and use it.
    [identityAttr removeObjectForKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef*)&identity);
    CHECK_KEYCHAIN_STATUS(@"retrieve wpj identity ref");;
    if (CFGetTypeID(identity) != SecIdentityGetTypeID())
    {
        CFRelease(identity);
        ADAuthenticationError* adError =
        [ADAuthenticationError unexpectedInternalError:@"Wrong object type returned from identity query"
                                         correlationId:context.correlationId];
        
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    //Get the certificate and data
    status = SecIdentityCopyCertificate(identity, &certificate);
    CHECK_KEYCHAIN_STATUS(@"copy identity certificate");
    
    status = SecIdentityCopyPrivateKey(identity, &privateKey);
    CHECK_KEYCHAIN_STATUS(@"copy identity private key");
    
    certificateSubject = (NSString *)CFBridgingRelease(SecCertificateCopySubjectSummary(certificate));
    certificateData = (NSData *)CFBridgingRelease(SecCertificateCopyData(certificate));
    
    if(!(identity && certificate && certificateSubject && certificateData && privateKey && certificateIssuer))
    {
        // We never should hit this error anyways, as any of this stuff being missing will cause failures farther up.
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Missing some piece of WPJ data" correlationId:context.correlationId];
        
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    {
        ADRegistrationInformation *info = [[ADRegistrationInformation alloc] initWithSecurityIdentity:identity
                                                                                certificateIssuer:certificateIssuer
                                                                                      certificate:certificate
                                                                               certificateSubject:certificateSubject
                                                                                  certificateData:certificateData
                                                                                       privateKey:privateKey];
        return info;
    }
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
    return nil;
}

@end

