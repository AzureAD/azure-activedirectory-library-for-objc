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
#import "ADRegistrationInformation.h"
#import "ADWorkPlaceJoinConstants.h"
#import "ADLogger+Internal.h"
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
                                                correlationId:correlationId];\
            if (error) { *error = adError; } \
        } \
        return nil; \
    } \
}


+ (ADRegistrationInformation*)getRegistrationInformation:(NSUUID *)correlationId
                                                   error:(ADAuthenticationError * __autoreleasing *)error
{
    NSString* teamId = [self keychainTeamId];
    if (!teamId)
    {
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Unable to retrieve team ID from keychain." correlationId:correlationId];
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    NSString* sharedAccessGroup = [NSString stringWithFormat:@"%@.com.microsoft.workplacejoin", teamId];
    
    AD_LOG_VERBOSE_F(@"Attempting to get registration information - ", nil, @"%@ shared access Group", sharedAccessGroup);
    
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSString *certificateIssuer = nil;
    NSString *userPrincipalName = nil;
    
    NSMutableDictionary *identityAttr = [[NSMutableDictionary alloc] init];
    SAFE_ARC_AUTORELEASE(identityAttr);
    [identityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    [identityAttr setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
    [identityAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
    
    CFDictionaryRef result = NULL;
    OSStatus status = noErr;
    //get the issuer information
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef *)&result);
    CHECK_KEYCHAIN_STATUS(@"retrieve wpj identity attr");
            
    NSDictionary *  cerDict = (__bridge NSDictionary *) result;
    assert([cerDict isKindOfClass:[NSDictionary class]]);
    NSData* issuer = [cerDict objectForKey:(__bridge id)kSecAttrIssuer];
    certificateIssuer = [[NSString alloc] initWithData:issuer encoding:NSISOLatin1StringEncoding];
    SAFE_ARC_AUTORELEASE(certificateIssuer);
    CFRelease(result);
    result = NULL;
    
    // now get the identity out and use it.
    [identityAttr removeObjectForKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef*)&identity);
    CFBridgingRelease(identity)
    CHECK_KEYCHAIN_STATUS(@"retrieve wpj identity ref");;
    if (CFGetTypeID(identity) != SecIdentityGetTypeID())
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError unexpectedInternalError:@"Wrong object type returned from identity query"
                                         correlationId:correlationId];
        
        if (error)
        {
            *error = adError;
        }
        return nil;
    }
    //Get the certificate and data
    status = SecIdentityCopyCertificate(identity, &certificate);
    CFBridgingRelease(certificate);
    CHECK_KEYCHAIN_STATUS(@"copy identity certificate");
    
    status = SecIdentityCopyPrivateKey(identity, &privateKey);
    CFBridgingRelease(privateKey);
    CHECK_KEYCHAIN_STATUS(@"copy identity private key");
    
    certificateSubject = (NSString *)CFBridgingRelease(SecCertificateCopySubjectSummary(certificate));
    certificateData = (NSData *)CFBridgingRelease(SecCertificateCopyData(certificate));
    
    if(!(identity && certificate && certificateSubject && certificateData && privateKey && certificateIssuer))
    {
        // We never should hit this error anyways, as any of this stuff being missing will cause failures farther up.
        ADAuthenticationError* adError = [ADAuthenticationError unexpectedInternalError:@"Missing some piece of WPJ data" correlationId:correlationId];
        
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
    
    ADRegistrationInformation *info = [[ADRegistrationInformation alloc] initWithSecurityIdentity:identity
                                                                                userPrincipalName:userPrincipalName
                                                                                certificateIssuer:certificateIssuer
                                                                                      certificate:certificate
                                                                               certificateSubject:certificateSubject
                                                                                  certificateData:certificateData
                                                                                       privateKey:privateKey];
    SAFE_ARC_AUTORELEASE(info);
    return info;
}

+ (NSString*)keychainTeamId
{
    static dispatch_once_t s_once;
    static NSString* s_keychainTeamId = nil;
    
    dispatch_once(&s_once, ^{
        s_keychainTeamId = [self retrieveTeamIDFromKeychain];
        SAFE_ARC_RETAIN(s_keychainTeamId);
        AD_LOG_INFO(([NSString stringWithFormat:@"Using \"%@\" Team ID for Keychain.", s_keychainTeamId]), nil, nil);
    });
    
    return s_keychainTeamId;
}

+ (NSString*)retrieveTeamIDFromKeychain
{
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (__bridge id)(kSecClassGenericPassword), kSecClass,
                           @"bundleSeedID", kSecAttrAccount,
                           @"", kSecAttrService,
                           (id)kCFBooleanTrue, kSecReturnAttributes,
                           nil];
    CFDictionaryRef result = nil;
    
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    
    if (status == errSecItemNotFound)
    {
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    }
    
    if (status != errSecSuccess)
    {
        return nil;
    }
    
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge id)(kSecAttrAccessGroup)];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [components firstObject];
    
    CFRelease(result);
    
    return [bundleSeedID length] ? bundleSeedID : nil;
}

@end

