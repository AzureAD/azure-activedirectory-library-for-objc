//
//  WorkPlaceJoinUtil.m
//  WorkPlaceJoinAPI
//
//  Created by Roger Toma on 3/19/14.
//  Copyright (c) 2014 Roger Toma. All rights reserved.
//

#import "WorkPlaceJoinUtil.h"
#import "RegistrationInformation.h"
#import "WorkPlaceJoinConstants.h"

@implementation WorkPlaceJoinUtil

WorkPlaceJoinUtil* wpjUtilManager = nil;

+ (WorkPlaceJoinUtil*) WorkPlaceJoinUtilManager;
{
    if (!wpjUtilManager)
    {
        wpjUtilManager = [[self alloc] init];
    }
    
    return wpjUtilManager;
}

- (NSData *)getPrivateKeyForAccessGroup: (NSString*)sharedAccessGroup
                   privateKeyIdentifier: (NSString*) privateKey
                                  error: (NSError**) error
{
    [self Log:[NSString stringWithFormat:@"Getting private key from %@ shared access Group",
                            sharedAccessGroup]];
    OSStatus status = noErr;
    CFDataRef item = NULL;
    NSData *keyData = nil;
    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    
    //NSData *privateKeyTag = [NSData dataWithBytes:[privateKey UTF8String] length:privateKey.length];
    
    //[privateKeyAttr setObject:privateKeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKeyAttr setObject:(__bridge id)(kSecAttrKeyTypeRSA) forKey:(__bridge id<NSCopying>)(kSecAttrKeyType)];
    [privateKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnData)];
#if !TARGET_IPHONE_SIMULATOR
    [privateKeyAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKeyAttr, (CFTypeRef*)&item);
    
    if(item != NULL)
    {
        keyData = (__bridge_transfer NSData*)item;
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

- (RegistrationInformation*)getRegistrationInformation: (NSString*) sharedAccessGroup
                                                 error: (NSError**) error
{
    [self Log:[NSString stringWithFormat:@"Attempting to get registration information from %@ shared access keychain",
                            sharedAccessGroup]];
    
    SecIdentityRef identity = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef privateKey = NULL;
    NSString *certificateSubject = nil;
    NSData *certificateData = nil;
    NSData *privateKeyData = nil;
    NSString *certificateProperties = nil;
    NSString *userPrincipalName = nil;
    error = nil;
    
    NSMutableDictionary *identityAttr = [[NSMutableDictionary alloc] init];
    [identityAttr setObject:(__bridge id)kSecClassIdentity forKey:(__bridge id)kSecClass];
    [identityAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id<NSCopying>)(kSecReturnRef)];
    
#if !TARGET_IPHONE_SIMULATOR
    [identityAttr setObject:sharedAccessGroup forKey:(__bridge id)kSecAttrAccessGroup];
#endif
    
    SecItemCopyMatching((__bridge CFDictionaryRef)identityAttr, (CFTypeRef*)&identity);
    
    //Get the identity
    if(identity)
    {
        [self Log:@"Found identity in keychain"];
        //Get the certificate and data
        SecIdentityCopyCertificate(identity, &certificate);
        if(certificate)
        {
            [self Log:@"Found certificate in keychain"];
            certificateSubject = (__bridge NSString *)(SecCertificateCopySubjectSummary(certificate));
            certificateData = (__bridge NSData *)(SecCertificateCopyData(certificate));
        }
        
        //Get the private key and data
        SecIdentityCopyPrivateKey(identity, &privateKey);
        if(privateKey)
        {
            [self Log:@"Retrieved privatekey"];
            privateKeyData = [self getPrivateKeyForAccessGroup:sharedAccessGroup privateKeyIdentifier:privateKeyIdentifier error:error];
        }
        
        if (error)
        {
            if (certificateSubject)
                CFRelease((__bridge CFTypeRef)(certificateSubject));
            if (certificateData)
                CFRelease((__bridge CFTypeRef)(certificateData));
            
            return nil;
        }
    }
    
    if(identity && certificate && certificateSubject && certificateData && privateKey && privateKeyData)
    {
        RegistrationInformation *info = [[RegistrationInformation alloc] initWithSecurityIdentity:identity
                                                                                userPrincipalName:userPrincipalName
                                                                            certificateProperties:certificateProperties
                                                                                      certificate:certificate
                                                                               certificateSubject:certificateSubject
                                                                                  certificateData:certificateData
                                                                                       privateKey:privateKey
                                                                                   privateKeyData:privateKeyData];
        
        CFRelease(identity);
        CFRelease(certificate);
        CFRelease(privateKey);
        CFRelease((__bridge CFTypeRef)(certificateSubject));
        CFRelease((__bridge CFTypeRef)(certificateData));
        
        
        return info;
    }
    else
    {
        [self Log:[NSString stringWithFormat:@"Unable to extract a workplace join identity from the %@ shared access keychain",
                                sharedAccessGroup]];
        
        if (certificateSubject)
            CFRelease((__bridge CFTypeRef)(certificateSubject));
        if (certificateData)
            CFRelease((__bridge CFTypeRef)(certificateData));
        
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
    
    [self Log:@"Looking for application identifier prefix in app data"];
    NSUserDefaults* c = [NSUserDefaults standardUserDefaults];
    NSString* appIdentifierPrefix = [c objectForKey:applicationIdentifierPrefix];

    if (!appIdentifierPrefix)
    {
        appIdentifierPrefix = [self bundleSeedID];
        
        [self Log:@"Storing application identifier prefix in app data"];
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


- (void) Log: (NSString*) logMessage
{
    if ([self workplaceJoin].delegate)
    {
        [[self workplaceJoin].delegate workplaceClient:[self workplaceJoin] logMessage:logMessage];
    }
    else
    {
        NSLog(@"%@", logMessage);
    }
}



@end

