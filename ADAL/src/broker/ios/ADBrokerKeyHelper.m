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
#import "MSIDOAuth2Constants.h"
#import "ADHelpers.h"
#import "MSIDPkeyAuthHelper.h"
#import "NSData+MSIDExtensions.h"

static NSData* s_symmetricKeyOverride = nil;

@implementation ADBrokerKeyHelper

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

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

- (BOOL)createBrokerKey:(ADAuthenticationError* __autoreleasing*)error
{
    uint8_t * symmetricKey = NULL;
    OSStatus err = errSecSuccess;
    
    symmetricKey = calloc( 1, kChosenCipherKeySize * sizeof(uint8_t));
    if (!symmetricKey)
    {
        UNEXPECTED_KEY_ERROR;
        return NO;
    }
    
    err = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
    if (err != errSecSuccess)
    {
        MSID_LOG_ERROR(nil, @"Failed to copy random bytes for broker key. Error code: %d", (int)err);
        
        UNEXPECTED_KEY_ERROR;
        free(symmetricKey);
        return NO;
    }
    
    NSData* keyData = [[NSData alloc] initWithBytes:symmetricKey length:kChosenCipherKeySize * sizeof(uint8_t)];
    free(symmetricKey);
    
    NSDictionary* symmetricKeyAttr =
    @{
      (id)kSecClass : (id)kSecClassKey,
      (id)kSecAttrKeyClass : (id)kSecAttrKeyClassSymmetric,
      (id)kSecAttrApplicationTag : _symmetricTag,
      (id)kSecAttrKeyType : @(CSSM_ALGID_AES),
      (id)kSecAttrKeySizeInBits : @(kChosenCipherKeySize << 3),
      (id)kSecAttrEffectiveKeySize : @(kChosenCipherKeySize << 3),
      (id)kSecAttrCanEncrypt : @YES,
      (id)kSecAttrCanDecrypt : @YES,
      (id)kSecValueData : keyData,
      };
    
    // First delete current symmetric key.
    if (![self deleteSymmetricKey:error])
    {
        return NO;
    }
    
    err = SecItemAdd((__bridge CFDictionaryRef) symmetricKeyAttr, NULL);
    
    if(err != errSecSuccess)
    {
        UNEXPECTED_KEY_ERROR;
        return NO;
    }
    
    [self setSymmetricKey:keyData];
    
    return YES;
}

- (BOOL)deleteSymmetricKey: (ADAuthenticationError* __autoreleasing*) error
{
    OSStatus err = noErr;
    
    NSDictionary* symmetricKeyQuery =
    @{
      (id)kSecClass : (id)kSecClassKey,
      (id)kSecAttrApplicationTag : _symmetricTag,
      (id)kSecAttrKeyType : @(CSSM_ALGID_AES),
      };
    
    // Delete the symmetric key.
    err = SecItemDelete((__bridge CFDictionaryRef)symmetricKeyQuery);
    
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
        return NO;
    }
    
    _symmetricKey = nil;
    return YES;
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
    
    if (_symmetricKey)
    {
        return _symmetricKey;
    }
    
    if (s_symmetricKeyOverride)
    {
        return s_symmetricKeyOverride;
    }
    
    NSDictionary* symmetricKeyQuery =
    @{
      (id)kSecClass : (id)kSecClassKey,
      (id)kSecAttrApplicationTag : _symmetricTag,
      (id)kSecAttrKeyType : @(CSSM_ALGID_AES),
      (id)kSecReturnData : @(YES),
      };
    
    // Get the key bits.
    CFDataRef symmetricKey = nil;
    err = SecItemCopyMatching((__bridge CFDictionaryRef)symmetricKeyQuery, (CFTypeRef *)&symmetricKey);
    if (err == errSecSuccess)
    {
        [self setSymmetricKey:(__bridge NSData*)symmetricKey];
        CFRelease(symmetricKey);
        return _symmetricKey;
    }
    
    if (createKeyIfDoesNotExist)
    {
        [self createBrokerKey:error];
    }
    
    return _symmetricKey;
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

- (void)setSymmetricKey:(NSData *)symmetricKey
{
    _symmetricKey = symmetricKey;
}

+ (NSData *)symmetricKey
{
    return s_symmetricKeyOverride;
}

+ (void)setSymmetricKey:(NSString *)base64Key
{
    s_symmetricKeyOverride = base64Key ?  [NSData msidDataFromBase64UrlEncodedString:base64Key] : nil;
}

+ (NSDictionary *)decryptBrokerResponse:(NSDictionary *)response correlationId:(NSUUID *)correlationId error:(ADAuthenticationError * __autoreleasing *)error
{
    NSString *hash = [response valueForKey:ADAL_BROKER_HASH_KEY];
    if (!hash)
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_HASH_MISSING, @"Key hash is missing from the broker response", correlationId);
        return nil;
    }

    NSString *encryptedBase64Response = [response valueForKey:ADAL_BROKER_RESPONSE_KEY];
    NSString *msgVer = [response valueForKey:ADAL_BROKER_MESSAGE_VERSION];
    NSInteger protocolVersion = 1;
    if (msgVer)
    {
        protocolVersion = [msgVer integerValue];
    }

    //decrypt response first
    ADBrokerKeyHelper *brokerHelper = [[ADBrokerKeyHelper alloc] init];
    ADAuthenticationError *decryptionError = nil;
    NSData *encryptedResponse = [NSData msidDataFromBase64UrlEncodedString:encryptedBase64Response];
    NSData *decrypted = [brokerHelper decryptBrokerResponse:encryptedResponse
                                                    version:protocolVersion
                                                      error:&decryptionError];

    if (!decrypted)
    {
        AUTH_ERROR_UNDERLYING(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED, @"Failed to decrypt broker message", decryptionError, correlationId)
        return nil;
    }

    NSString *decryptedString = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    if (!decryptedString)
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_DECRYPTION_FAILED, @"Failed to initialize decrypted string", correlationId);
        return nil;
    }

    //now compute the hash on the unencrypted data
    NSString *actualHash = [MSIDPkeyAuthHelper computeThumbprint:decrypted];
    if(![hash isEqualToString:actualHash])
    {
        AUTH_ERROR(AD_ERROR_TOKENBROKER_RESPONSE_HASH_MISMATCH, @"Decrypted response does not match the hash", correlationId);
        return nil;
    }

    // create response from the decrypted payload
    NSDictionary *decryptedResponse = [NSDictionary msidDictionaryFromWWWFormURLEncodedString:decryptedString];
    [ADHelpers removeNullStringFrom:decryptedResponse];

    return decryptedResponse;
}

@end
