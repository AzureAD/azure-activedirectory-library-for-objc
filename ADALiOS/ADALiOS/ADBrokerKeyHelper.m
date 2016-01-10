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

#import <Foundation/Foundation.h>
#import "ADALiOS.h"
#import "ADAuthenticationError.h"
#import "ADErrorCodes.h"
#import "ADBrokerKeyHelper.h"
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import "ADLogger+Internal.h"

@implementation ADBrokerKeyHelper

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

@synthesize symmetricTag = _symmetricTag;
@synthesize symmetricKeyRef = _symmetricKeyRef;

static const uint8_t symmetricKeyIdentifier[]   = kSymmetricKeyTag;

#define UNEXPECTED_KEY_ERROR { \
    if (error) { \
        *error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:@"Could not create broker key." code:AD_ERROR_UNEXPECTED userInfo:nil] errorDetails:nil]; \
    } \
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    // Tag data to search for keys.
    _symmetricTag = [[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)];

    
    return self;
}

- (void)createBrokerKey:(ADAuthenticationError* __autoreleasing*)error
{
    uint8_t * symmetricKey = NULL;
    OSStatus err = errSecSuccess;
    
    symmetricKey = malloc( kChosenCipherKeySize * sizeof(uint8_t));
    if (!symmetricKey)
    {
        UNEXPECTED_KEY_ERROR;
        return;
    }
    
    memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);
    
    err = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
    if (err != errSecSuccess)
    {
        AD_LOG_ERROR(@"Failed to copy random bytes for broker key.", err, nil, nil);
        UNEXPECTED_KEY_ERROR;
        free(symmetricKey);
        return;
    }
    
    NSData* keyData = [[NSData alloc] initWithBytes:symmetricKey length:kChosenCipherKeySize * sizeof(uint8_t)];
    free(symmetricKey);
    
    [self createBrokerKeyWithBytes:keyData error:error];
    [keyData release];
}

- (void)createBrokerKeyWithBytes:(NSData*)bytes
                           error:(ADAuthenticationError* __autoreleasing*)error
{
    OSStatus err = noErr;
    
    // First delete current symmetric key.
    [self deleteSymmetricKey:error];
    
    // Container dictionary
    NSMutableDictionary *symmetricKeyAttr = [[NSMutableDictionary alloc] init];
    [symmetricKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [symmetricKeyAttr setObject:(__bridge id)(kSecClassGenericPassword) forKey:(__bridge id)kSecAttrKeyClass];
    [symmetricKeyAttr setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)]  forKey:(__bridge id)kSecAttrEffectiveKeySize];
    [symmetricKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanEncrypt];
    [symmetricKeyAttr setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanDecrypt];
    [symmetricKeyAttr setObject:bytes forKey:(__bridge id)kSecValueData];
    
    err = SecItemAdd((__bridge CFDictionaryRef) symmetricKeyAttr, NULL);
    SAFE_ARC_RELEASE(symmetricKeyAttr);
    
    if(err != errSecSuccess)
    {
        UNEXPECTED_KEY_ERROR;
    }
    
    _symmetricKeyRef = bytes;
}

- (void)deleteSymmetricKey: (ADAuthenticationError* __autoreleasing*) error
{
    OSStatus err = noErr;
    
    NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
    
    // Set the symmetric key query dictionary.
    [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
    
    // Delete the symmetric key.
    err = SecItemDelete((__bridge CFDictionaryRef)querySymmetricKey);
    SAFE_ARC_RELEASE(querySymmetricKey);
    
    // Try to delete something that doesn't exist isn't really an error
    if(err != errSecSuccess && err != errSecItemNotFound)
    {
        NSString* details = [NSString stringWithFormat:@"Failed to delete broker key with error: %d", (int)err];
        NSError* nserror = [NSError errorWithDomain:@"Could not delete broker key."
                                               code:AD_ERROR_UNEXPECTED
                                           userInfo:nil];
        *error = [ADAuthenticationError errorFromNSError:nserror
                                            errorDetails:details];
    }
    
    _symmetricKeyRef = nil;
}

- (NSData*)getBrokerKey:(ADAuthenticationError* __autoreleasing*)error
{
    return [self getBrokerKey:error
                       create:YES];
}

- (NSData*)getBrokerKey:(ADAuthenticationError* __autoreleasing*)error
                 create:(BOOL)createKeyIfDoesNotExist
{
    OSStatus err = noErr;
    
    if (_symmetricKeyRef)
    {
        return _symmetricKeyRef;
    }
    
    NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
    
    // Set the private key query dictionary.
    [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
    [querySymmetricKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits.
    CFDataRef symmetricKey = nil;
    err = SecItemCopyMatching((__bridge CFDictionaryRef)querySymmetricKey, (CFTypeRef *)&symmetricKey);
    SAFE_ARC_RELEASE(querySymmetricKey);
    if (err == errSecSuccess)
    {
        _symmetricKeyRef = CFBridgingRelease(symmetricKey);
        return _symmetricKeyRef;
    }
    
    if (createKeyIfDoesNotExist)
    {
        [self createBrokerKey:error];
    }
    
    return _symmetricKeyRef;
}


- (NSData*)decryptBrokerResponse:(NSData*)response
                         version:(NSInteger)version
                          error:(ADAuthenticationError* __autoreleasing*)error
{
    NSData* keyData = [self getBrokerKey:error];
    const void* keyBytes = nil;
    size_t keySize = 0;
    
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    
    if (version > 1)
    {
        keyBytes = [keyData bytes];
        keySize = [keyData length];
    }
    else
    {
        NSString *key = [[NSString alloc] initWithData:keyData encoding:NSASCIIStringEncoding];
        bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
        // fetch key data
        [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
        SAFE_ARC_RELEASE(key);
        keyBytes = keyPtr;
        keySize = kCCKeySizeAES256;
    }
    
    return [self decryptBrokerResponse:response key:keyBytes size:keySize error:error];
}

- (NSData*)decryptBrokerResponse:(NSData *)response
                             key:(const void*)key
                            size:(size_t)size
                           error:(ADAuthenticationError *__autoreleasing *)error
{
    NSUInteger dataLength = [response length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    if(!buffer){
        *error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:ADAuthenticationErrorDomain code:AD_ERROR_UNEXPECTED userInfo:nil]
                                            errorDetails:@"Failed to allocate memory for decryption"];
        return nil;
    }

    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          key, size,
                                          NULL /* initialization vector (optional) */,
                                          [response bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    
    return nil;
}

@end;