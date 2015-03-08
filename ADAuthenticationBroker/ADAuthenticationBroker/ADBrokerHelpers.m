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
#import "NSString+ADBrokerHelperMethods.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
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
    unsigned char sha256Buffer[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(inputData.bytes, (CC_LONG)inputData.length, sha256Buffer);
    
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i)
    {
        [fingerprint appendFormat:@"%02x ",sha256Buffer[i]];
    }
    NSString* thumbprint = [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    thumbprint = [thumbprint uppercaseString];
    return [thumbprint stringByReplacingOccurrencesOfString:@" " withString:@""];
}

+(NSData*) encryptData: (NSData*) data
                   key: (NSString*) key
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256+1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
    
}


+ (NSString*) computeKDFInCounterMode:(NSData*)key
                              context:(NSString*)ctx
                                label:(NSString*)label
{
    uint8_t* keyDerivationKey = (uint8_t*)[key bytes];
    
    const unsigned char bytes[] = { 0x00 };
    NSData *nullData = [NSData dataWithBytes:bytes length:1];
    NSString *nullString = [[NSString alloc] initWithData:nullData encoding:NSUTF8StringEncoding];
    
    NSString* fixed = [NSString stringWithFormat:@"%@%@%@%d", ctx, nullString, label, 256];
    uint8_t* retval = [ADBrokerHelpers KDFCounterMode:keyDerivationKey
                      outputSizeBit:256
                         fixedInput:(uint8_t *)fixed.UTF8String
             keyDerivationKeyLength:32
                   fixedInputLength:[fixed length]];
    
    char             hexmac[2 * CC_SHA256_DIGEST_LENGTH + 1];
    char             *p;
    
    p = hexmac;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++ ) {
        snprintf( p, 3, "%02x", retval[ i ] );
        p += 2;
    }
    
    NSString* string = [NSString stringWithUTF8String:hexmac];
    return [ NSString Base64EncodeData:[string dataUsingEncoding:NSUTF8StringEncoding] ];
}



+(uint8_t*) updateDataInput: (uint8_t) ctr
                 fixedInput:(uint8_t*) fixedInput
           fixedInputLength:(int) fixedInput_length
{
    uint8_t* tmpFixedInput = malloc(fixedInput_length + 1);
    tmpFixedInput[0] = ctr;
    memcpy(tmpFixedInput + 1, fixedInput, fixedInput_length * sizeof(uint8_t));
    return tmpFixedInput;
}

+(uint8_t*) KDFCounterMode:(uint8_t*) keyDerivationKey
             outputSizeBit:(int) outputSizeBit
                fixedInput:(uint8_t*) fixedInput
    keyDerivationKeyLength:(int) keyDerivationKey_length
          fixedInputLength: (int) fixedInput_length
{
    
    CCHmacContext hmacContext;
    uint8_t ctr;
    uint8_t* KI;
    uint8_t* keyDerivated;
    uint8_t* dataInput;
    int len;
    int numCurrentElements;
    int len_bytes;
    int numCurrentElements_bytes;
    int prfOutputSizeBit = 256;
    
    numCurrentElements = 0;
    ctr = 1;
    keyDerivated = malloc(outputSizeBit/8);
    
    do{
        //update data using "ctr"
        dataInput = [ADBrokerHelpers updateDataInput:ctr
                                          fixedInput:fixedInput
                                    fixedInputLength:fixedInput_length];
        
        //init PRF function
        CCHmacInit(&hmacContext, kCCHmacAlgSHA256, keyDerivationKey, keyDerivationKey_length);
        
        //account the +1 for ctr
        CCHmacUpdate(&hmacContext, dataInput, (fixedInput_length+1));
        CCHmacFinal(&hmacContext, KI);
        
        //decide how many bytes (so the "length") copy for currently keyDerivated?
        if (prfOutputSizeBit >= outputSizeBit) {
            len = outputSizeBit;
        } else {
            len = MIN(prfOutputSizeBit, outputSizeBit - numCurrentElements);
        }
        
        //convert bits in byte
        len_bytes = len/8;
        numCurrentElements_bytes = numCurrentElements/8;
        
        //copy KI in part of keyDerivated
        memcpy((keyDerivated + numCurrentElements_bytes), KI, len_bytes * sizeof(uint8_t));
        
        //increment ctr and numCurrentElements copied in keyDerivated
        numCurrentElements = numCurrentElements + len;
        ctr++;
        
        //deallock space in memory
        free(dataInput);
        
    } while (numCurrentElements < outputSizeBit);
    
    return keyDerivated;
}


@end