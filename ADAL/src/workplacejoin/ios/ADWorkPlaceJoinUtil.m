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

ADWorkPlaceJoinUtil* wpjUtilManager = nil;

+ (ADWorkPlaceJoinUtil*) WorkPlaceJoinUtilManager;
{
    if (!wpjUtilManager)
    {
        wpjUtilManager = [[self alloc] init];
    }
    
    return wpjUtilManager;
}

- (NSData *)getPrivateKeyForAccessGroup: (NSString*) sharedAccessGroup
                   privateKeyIdentifier: (NSString*) privateKey
                                  error: (NSError**) error
{
    AD_LOG_VERBOSE_F(@"Getting private key - ", nil, @"%@ shared access Group", sharedAccessGroup);
    OSStatus status = noErr;
    CFDataRef item = NULL;
    NSData *keyData = nil;
    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    
    NSData *privateKeyTag = [NSData dataWithBytes:[privateKey UTF8String] length:privateKey.length];
    
    [privateKeyAttr setObject:privateKeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKeyAttr setObject:(__bridge id)(kSecAttrKeyTypeRSA) forKey:(__bridge id<NSCopying>)(kSecAttrKeyType)];
    [privateKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnData)];
#if !TARGET_IPHONE_SIMULATOR
    [privateKeyAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKeyAttr, (CFTypeRef*)&item);
    SAFE_ARC_RELEASE(privateKeyAttr);
    
    if(item != NULL)
    {
        keyData = (NSData*)item;
    }
    else if (status != errSecSuccess)
    {
        if (*error != NULL)
        {
            *error = [self buildNSErrorForDomain:errorDomain
                                       errorCode:sharedKeychainPermission
                                    errorMessage: [NSString stringWithFormat:unabletoReadFromSharedKeychain, sharedAccessGroup]
                                 underlyingError:nil
                                     shouldRetry:false];
        }
    }
    
    return keyData;
}



- (ADRegistrationInformation*)getRegistrationInformation: (NSString*) sharedAccessGroup
                                                   error: (NSError**) error
{
    AD_LOG_VERBOSE_F(@"Attempting to get registration information - ", nil, @"%@ shared access Group", sharedAccessGroup);
    
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSData *privateKeyData = nil;
    NSString *certificateIssuer = nil;
    NSString *userPrincipalName = nil;
    error = nil;
    
    NSMutableDictionary *identityAttr = [[NSMutableDictionary alloc] init];
    [identityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    [identityAttr setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
    
#if !TARGET_IPHONE_SIMULATOR
    [identityAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    
    CFDictionaryRef  result;
    OSStatus status = noErr;
    //get the issuer information
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef *) &result);
    
    if (status == noErr) {
        NSDictionary *  cerDict = (__bridge NSDictionary *) result;
        assert([cerDict isKindOfClass:[NSDictionary class]]);
        NSData* issuer = [cerDict objectForKey:(__bridge id)kSecAttrIssuer];
        certificateIssuer = [[NSString alloc] initWithData:issuer encoding:NSISOLatin1StringEncoding];
        CFRelease(result);
    } else {
        NSLog(@"error %d", (int) status);
    }
    
    // now get the identity out and use it.
    [identityAttr removeObjectForKey:(__bridge id<NSCopying>)(kSecReturnAttributes)];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef*)&identity);
    SAFE_ARC_RELEASE(identityAttr);
    
    //Get the identity
    if(status == errSecSuccess && identity)
    {
        AD_LOG_VERBOSE(@"Found identity in keychain", nil, nil);
        //Get the certificate and data
        SecIdentityCopyCertificate(identity, &certificate);
        if(certificate)
        {
            AD_LOG_VERBOSE(@"Found certificate in keychain", nil, nil);
            certificateSubject = (NSString *)CFBridgingRelease(SecCertificateCopySubjectSummary(certificate));
            certificateData = (NSData *)CFBridgingRelease(SecCertificateCopyData(certificate));
        }
        
        //Get the private key and data
        status = SecIdentityCopyPrivateKey(identity, &privateKey);
        if (status != errSecSuccess)
        {
            [certificateIssuer release];
            return nil;
        }
        
    }
    
    if(identity && certificate && certificateSubject && certificateData && privateKey && certificateIssuer)
    {
        ADRegistrationInformation *info = [[ADRegistrationInformation alloc] initWithSecurityIdentity:identity
                                                                                    userPrincipalName:userPrincipalName
                                                                                    certificateIssuer:certificateIssuer
                                                                                          certificate:certificate
                                                                                   certificateSubject:certificateSubject
                                                                                      certificateData:certificateData
                                                                                           privateKey:privateKey
                                                                                       privateKeyData:privateKeyData];
        SAFE_ARC_RELEASE(certificateIssuer);
        SAFE_ARC_AUTORELEASE(info);
        return info;
    }
    else
    {
        AD_LOG_VERBOSE_F(@"Unable to extract a workplace join identity for", nil, @"%@ shared access keychain",
                         sharedAccessGroup);
        SAFE_ARC_RELEASE(certificateIssuer);
        return nil;
    }
}

- (NSError*)getCertificateForAccessGroup: (NSString*)sharedAccessGroup
                                identity: (SecIdentityRef*) identity
                             certificate: (SecCertificateRef*) clientCertificate
{
    NSMutableDictionary *identityAttr = [[NSMutableDictionary alloc] init];
    [identityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    [identityAttr setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    
    
#if !TARGET_IPHONE_SIMULATOR
    [identityAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    
    SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef*)identity);
    
    OSStatus status = SecIdentityCopyCertificate(*identity, clientCertificate );
    SAFE_ARC_RELEASE(identityAttr);
    
    if (status == errSecSuccess)
    {
        return nil;
    }
    else
    {
        return [self buildNSErrorForDomain:errorDomain
                                 errorCode:sharedKeychainPermission
                              errorMessage: [NSString stringWithFormat:unabletoReadFromSharedKeychain, sharedAccessGroup]
                           underlyingError:nil
                               shouldRetry:false];
    }
    
    
}


- (NSError*) buildNSErrorForDomain:(NSString*)domain
                         errorCode:(NSInteger) errorCode
                      errorMessage:(NSString*) message
                   underlyingError:(NSError*) underlyingError
                       shouldRetry:(BOOL) retry
{
    NSMutableDictionary* details = [NSMutableDictionary dictionary];
    [details setValue:message forKey:NSLocalizedDescriptionKey];
    
    if (underlyingError != nil)
    {
        [details setValue:underlyingError forKey:NSUnderlyingErrorKey];
    }
    
    if (retry)
    {
        [details setValue:@"retry" forKey:NSLocalizedRecoverySuggestionErrorKey];
    }
    
    
    NSError *error = [NSError errorWithDomain:domain code:errorCode userInfo:details];
    return error;
}

- (NSData *)base64DataFromString: (NSString *)string
{
    unsigned char ch, accumulated[BASE64QUANTUMREP], outbuf[BASE64QUANTUM];
    const unsigned char *charString;
    NSMutableData *theData;
    const int OUTOFRANGE = 64;
    const unsigned char LASTCHARACTER = '=';
    
    if (string == nil)
    {
        return [NSData data];
    }
    
    for (int i = 0; i < BASE64QUANTUMREP; i++) {
        accumulated[i] = 0;
    }
    
    charString = (const unsigned char *)[string UTF8String];
    
    theData = [NSMutableData dataWithCapacity: [string length]];
    
    short accumulateIndex = 0;
    for (int index = 0; index < [string length]; index++) {
        
        ch = decodeBase64[charString [index]];
        
        if (ch < OUTOFRANGE)
        {
            short ctcharsinbuf = BASE64QUANTUM;
            
            if (charString [index] == LASTCHARACTER)
            {
                if (accumulateIndex == 0)
                {
                    break;
                }
                else if (accumulateIndex <= 2)
                {
                    ctcharsinbuf = 1;
                }
                else
                {
                    ctcharsinbuf = 2;
                }
                
                accumulateIndex = BASE64QUANTUM;
            }
            //
            // Accumulate 4 valid characters (ignore everything else)
            //
            accumulated [accumulateIndex++] = ch;
            
            //
            // Store the 6 bits from each of the 4 characters as 3 bytes
            //
            if (accumulateIndex == BASE64QUANTUMREP)
            {
                accumulateIndex = 0;
                
                outbuf[0] = (accumulated[0] << 2) | ((accumulated[1] & 0x30) >> 4);
                outbuf[1] = ((accumulated[1] & 0x0F) << 4) | ((accumulated[2] & 0x3C) >> 2);
                outbuf[2] = ((accumulated[2] & 0x03) << 6) | (accumulated[3] & 0x3F);
                
                for (int i = 0; i < ctcharsinbuf; i++)
                {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
        }
        
    }
    
    return theData;
}

- (NSString*)getApplicationIdentifierPrefix{
    
    AD_LOG_VERBOSE(@"Looking for application identifier prefix in app data", nil, nil);
    NSUserDefaults* c = [NSUserDefaults standardUserDefaults];
    NSString* appIdentifierPrefix = [c objectForKey:applicationIdentifierPrefix];
    
    if (!appIdentifierPrefix)
    {
        appIdentifierPrefix = [self bundleSeedID];
        
        AD_LOG_VERBOSE(@"Storing application identifier prefix in app data", nil, nil);
        NSUserDefaults* c = [NSUserDefaults standardUserDefaults];
        [c setObject:appIdentifierPrefix forKey:applicationIdentifierPrefix];
        [c synchronize];
    }
    
    return appIdentifierPrefix;
}

- (NSString*)bundleSeedID {
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (__bridge id)(kSecClassGenericPassword), kSecClass,
                           @"bundleSeedID", kSecAttrAccount,
                           @"", kSecAttrService,
                           (id)kCFBooleanTrue, kSecReturnAttributes,
                           nil];
    CFDictionaryRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound)
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status != errSecSuccess)
        return nil;
    NSString *accessGroup = [(__bridge NSDictionary *)result objectForKey:(__bridge id)(kSecAttrAccessGroup)];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [[components objectEnumerator] nextObject];
    SecItemDelete((__bridge CFDictionaryRef)(query));
    
    CFRelease(result);
    return bundleSeedID;
}

@end

