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
#import "ADAuthenticationError.h"
#import "ADErrorCodes.h"
#import "ADBrokerKeyHelper.h"
#import "ADKeyChainHelper.h"
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger kAlgorithmIVSize = kCCBlockSizeAES128;

@implementation ADBrokerKeyHelper

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

@synthesize symmetricTag = _symmetricTag;
@synthesize symmetricKeyRef = _symmetricKeyRef;

static const uint8_t symmetricKeyIdentifier[]   = kSymmetricKeyTag;

-(id) initHelper
{
    if (self = [super init])
    {
        // Tag data to search for keys.
        _symmetricTag = [[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)];
    }
    
    return self;
}


-(void) createBrokerKey: (ADAuthenticationError* __autoreleasing*) error
{
    OSStatus sanityCheck = noErr;
    uint8_t * symmetricKey = NULL;
    
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
    
    symmetricKey = malloc( kChosenCipherKeySize * sizeof(uint8_t) );
    memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);
    
    sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
    if(sanityCheck == errSecSuccess){
        self.symmetricKeyRef = [[NSData alloc] initWithBytes:(const void *)symmetricKey length:kChosenCipherKeySize];
        // Add the wrapped key data to the container dictionary.
        [symmetricKeyAttr setObject:_symmetricKeyRef
                             forKey:(__bridge id)kSecValueData];
        // Add the symmetric key to the keychain.
        sanityCheck = SecItemAdd((__bridge CFDictionaryRef) symmetricKeyAttr, NULL);
    }
    
    if(sanityCheck != errSecSuccess){
         *error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:@"Could not create broker key." code:AD_ERROR_UNEXPECTED userInfo:nil] errorDetails:nil];
    }
    
    if (symmetricKey)
    {
        free(symmetricKey);
    }
}

- (void)deleteSymmetricKey: (ADAuthenticationError* __autoreleasing*) error {
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
    
    // Set the symmetric key query dictionary.
    [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
    
    // Delete the symmetric key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)querySymmetricKey);
    
    if(sanityCheck != errSecSuccess){
        *error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:@"Could not delete broker key." code:AD_ERROR_UNEXPECTED userInfo:nil] errorDetails:@"Could not delete broker key."];
    }
    
    if(_symmetricKeyRef){
        CFRelease((__bridge CFTypeRef)(_symmetricKeyRef));
    }
}

-(NSData*) getBrokerKey: (ADAuthenticationError* __autoreleasing*) error
{
    return [self getBrokerKey:error createKeyIfDoesNotExist:YES];
}

-(NSData*) getBrokerKey: (ADAuthenticationError* __autoreleasing*) error
createKeyIfDoesNotExist: (BOOL) createKeyIfDoesNotExist
{
    OSStatus sanityCheck = noErr;
    NSData* symmetricKeyReturn = nil;
    CFDataRef symmetricKeyReturnRef;
    if (self.symmetricKeyRef == nil) {
        NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
        [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
        [querySymmetricKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
        
        // Get the key bits.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)querySymmetricKey, (CFTypeRef *)&symmetricKeyReturnRef);
        
        if(sanityCheck != errSecSuccess && createKeyIfDoesNotExist)
        {
            [self createBrokerKey:error];
            symmetricKeyReturn = self.symmetricKeyRef;
        } else {
            symmetricKeyReturn = (__bridge NSData *)symmetricKeyReturnRef;
            if (sanityCheck == noErr && symmetricKeyReturn != nil) {
                self.symmetricKeyRef = symmetricKeyReturn;
            } else {
                self.symmetricKeyRef = nil;
            }
        }
    } else {
        symmetricKeyReturn = self.symmetricKeyRef;
    }
    
    return symmetricKeyReturn;
}


-(NSData*) decryptBrokerResponse: (NSData*) response
                                 error:(ADAuthenticationError* __autoreleasing*) error
{
    NSData* keyData = [self getBrokerKey: error];
    NSString *key = [[NSString alloc] initWithData:keyData encoding:0];
    
    
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
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
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [response bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end;