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

#import "ADBrokerHelpers.h"
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>


const CCAlgorithm algorithm = kCCAlgorithmAES128;
const NSUInteger algorithmKeySize = kCCKeySizeAES128;
const NSUInteger algorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger algorithmIVSize = kCCBlockSizeAES128;

@implementation ADBrokerHelpers

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

+ (NSString*) computeHash:(NSData*) inputData{
    
    //compute SHA-1 thumbprint
    unsigned char sha1Buffer[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(inputData.bytes, (CC_LONG)inputData.length, sha1Buffer);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i)
    {
        [fingerprint appendFormat:@"%02x ",sha1Buffer[i]];
    }
    NSString* thumbprint = [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    thumbprint = [thumbprint uppercaseString];
    return [thumbprint stringByReplacingOccurrencesOfString:@" " withString:@""];
}



+(NSData*) encryptData: (NSString*) data
                   key: (NSData*) key
{
    NSData *iv = [ADBrokerHelpers randomDataOfLength:algorithmIVSize];
    
    size_t outLength;
    NSMutableData *cipherData = [NSMutableData dataWithLength:data.length +
                                 algorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     algorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     (__bridge const void *)(iv),// iv
                     (__bridge const void *)([data dataUsingEncoding:NSUTF8StringEncoding]), // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        //        if (error) {
        //            *error = [NSError errorWithDomain:kRNCryptManagerErrorDomain
        //                                         code:result
        //                                     userInfo:nil];
        //        }
        return nil;
    }
    
    return cipherData;
    
}


+ (NSData *)randomDataOfLength:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    NSAssert(result == 0, @"Unable to generate random bytes: %d",
             errno);
    
    return data;
}


@end