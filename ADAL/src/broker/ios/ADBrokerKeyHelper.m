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

#import <Foundation/Foundation.h>
#import "ADAL_Internal.h"
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
        *error = [ADAuthenticationError errorFromNSError:[NSError errorWithDomain:@"ADAL" code:AD_ERROR_TOKENBROKER_FAILED_TO_CREATE_KEY userInfo:nil] errorDetails:@"Could not create broker key." correlationId:nil]; \
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
                                            errorDetails:details
                                           correlationId:nil];
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
    
    if(!buffer)
    {
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
    
    ADAuthenticationError* adError = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_TOKENBROKER_DECRYPTION_FAILED
                                                                            protocolCode:nil
                                                                            errorDetails:@"Failed to decrypt the broker response"
                                                                           correlationId:nil];
    if (error)
    {
        *error = adError;
    }
    return nil;
}

@end;