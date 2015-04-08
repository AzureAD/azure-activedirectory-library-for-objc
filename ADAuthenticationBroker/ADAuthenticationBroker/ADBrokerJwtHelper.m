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

#import "ADBrokerJwtHelper.h"
#import "NSString+ADBrokerHelperMethods.h"
#import "ADBrokerConstants.h"
#import "ADBrokerJWEResponse.h"

#include "xCryptLib.h"

@implementation ADBrokerJwtHelper

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 2048;
const uint32_t PADDING = kSecPaddingNone;
const NSString* Label = @"AzureAD-SecureConversation";

+(NSData*) getSessionKeyFromEncryptedJWT:(NSString*) encryptedJwt
                             privateKeyRef:(SecKeyRef) privateKeyRef
                                     error:(NSError**) error;
{
    ADBrokerJWEResponse* response = [[ADBrokerJWEResponse alloc] initWithRawJWE:encryptedJwt];
    NSData* decryptedResponse = [ADBrokerJwtHelper decryptData:response.encryptedKey
                                                  privateKeyRef:privateKeyRef
                                                          error:error];
    
    return decryptedResponse;
}


+(NSData*) decryptData:(NSData*) encryptedJwt
         privateKeyRef:(SecKeyRef) privateKeyRef
                 error:(NSError**) error
{
    size_t plainBufferSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *plainBuffer = malloc(plainBufferSize);
    uint8_t *cipherBuffer = (uint8_t*)[encryptedJwt bytes];
    size_t cipherBufferSize = [encryptedJwt length];
    
    OSStatus status = SecKeyDecrypt(privateKeyRef,
                  kSecPaddingOAEP,
                  cipherBuffer,
                  cipherBufferSize,
                  plainBuffer,
                  &plainBufferSize);
    if(status != errSecSuccess)
    {
        return nil;
    }
    
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
//    NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding]; return decryptedString;
    return  decryptedData;
}


+(NSString*) createSignedJWTforHeader:(NSDictionary*) header
                              payload:(NSDictionary*) payload
                           signingKey:(SecKeyRef) signingKey
{
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@",
                              [[ADBrokerJwtHelper createJSONFromDictionary:header] adBase64UrlEncode],
                              [[ADBrokerJwtHelper createJSONFromDictionary:payload] adBase64UrlEncode]];
    NSData* signedData = [ADBrokerJwtHelper sign:signingKey
                                            data:[signingInput dataUsingEncoding:NSUTF8StringEncoding]];
    NSString* signedEncodedDataString = [NSString Base64EncodeData: signedData];
    
    return [NSString stringWithFormat:@"%@.%@", signingInput, signedEncodedDataString];
}


+(NSString*) createSignedJWTUsingKeyDerivation:(NSDictionary*) header
                                       payload:(NSDictionary*) payload
                                       context:(NSString*) context
                                  symmetricKey:(NSString*) symmetricKey
{
NSMutableDictionary *options = [[NSMutableDictionary alloc] init];

SecKeyRef privateKeyRef = NULL;

//change to the actual password you used here
[options setObject:@"!@#EWQ" forKey:(__bridge id)kSecImportExportPassphrase];
CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)[symmetricKey dataUsingEncoding:NSUTF8StringEncoding], (__bridge CFDictionaryRef)options, &items);

if (securityError == noErr && CFArrayGetCount(items) > 0) {
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
    
    securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    if (securityError != noErr) {
        privateKeyRef = NULL;
    }
}

CFRelease(items);
    
    return nil;
}



+(NSData *) sign: (SecKeyRef) privateKey
            data:(NSData *) plainData
{
    NSData* signedHash = nil;
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    if(!signedHashBytes){
        return nil;
    }
    
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if(!hashBytes){
        free(signedHashBytes);
        return nil;
    }
    
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        if (hashBytes)
            free(hashBytes);
        if (signedHashBytes)
            free(signedHashBytes);
        return nil;
    }
    
    OSStatus status = SecKeyRawSign(privateKey,
                                    kSecPaddingPKCS1SHA256,
                                    hashBytes,
                                    hashBytesSize,
                                    signedHashBytes,
                                    &signedHashBytesSize);
    
    if(status == errSecSuccess)
    {
        signedHash = [NSData dataWithBytes:signedHashBytes
                                    length:(NSUInteger)signedHashBytesSize];
    }
    
    if (hashBytes) {
        free(hashBytes);
    }
    
    if (signedHashBytes) {
        free(signedHashBytes);
    }
    return signedHash;
}


+ (NSString *) createJSONFromDictionary:(NSDictionary *) dictionary{
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (jsonData) {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return nil;
}


@end
