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


#import "NSString+ADHelperMethods.h"
#import "ADBrokerHelpers.h"
#import "ADBrokerBase64Additions.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

const CCAlgorithm algorithm = kCCAlgorithmAES128;
const NSUInteger algorithmKeySize = kCCKeySizeAES128;
const NSUInteger algorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger algorithmIVSize = kCCBlockSizeAES128;

const NSString* Label = @"AzureAD-SecureConversation";

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


+ (NSData*) computeKDFInCounterMode:(NSData*)key
                              context:(NSData*)ctx
{
    NSData* labelData = [Label dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* mutData = [NSMutableData new];
    [mutData appendBytes:labelData.bytes length:labelData.length];
    Byte bytes[] = {0x00};
    [mutData appendBytes:bytes length:1];
    [mutData appendBytes:ctx.bytes length:ctx.length];
    int32_t size = CFSwapInt32HostToBig(256); //make big-endian
    [mutData appendBytes:&size length:sizeof(size)];
    
    uint8_t* pbDerivedKey = [ADBrokerHelpers KDFCounterMode:(uint8_t*)key.bytes
                   keyDerivationKeyLength:key.length
                                fixedInput:(uint8_t*)mutData.bytes
                         fixedInputLength:mutData.length];
    mutData = nil;
    NSData* dataToReturn = [NSData dataWithBytes:(const void *)pbDerivedKey length:32];
    free(pbDerivedKey);
    
    return dataToReturn;
}


+ (NSData*) convertBase64UrlStringToBase64NSData:(NSString*) base64UrlString
{
    
    return [NSData dataWithBase64String:[ADBrokerHelpers convertBase64UrlStringToBase64NSString:base64UrlString]];
}


+ (NSString*) convertBase64UrlStringToBase64NSString:(NSString*) base64UrlString
{
    base64UrlString = [base64UrlString stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    base64UrlString = [base64UrlString stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    NSString* base64PadCharacter = @"=";
    
    switch (base64UrlString.length % 4) // Pad
    {
        case 0:
            break; // No pad chars in this case
        case 2:
            base64UrlString = [NSString stringWithFormat:@"%@%@%@", base64UrlString, base64PadCharacter, base64PadCharacter];
            break; // Two pad chars
        case 3:
            base64UrlString = [NSString stringWithFormat:@"%@%@", base64UrlString, base64PadCharacter];
            break; // One pad char
    }
    
    return base64UrlString;
}


+ (uint8_t*) KDFCounterMode:(uint8_t*) keyDerivationKey
   keyDerivationKeyLength:(size_t) keyDerivationKeyLength
                fixedInput:(uint8_t*) fixedInput
         fixedInputLength:(size_t) fixedInputLength
{
    uint8_t ctr;
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    uint8_t* keyDerivated;
    uint8_t* dataInput;
    int len;
    int numCurrentElements;
    int numCurrentElements_bytes;
    int outputSizeBit = 256;
    
    numCurrentElements = 0;
    ctr = 1;
    keyDerivated = (uint8_t*)malloc(outputSizeBit/8); //output is 32 bytes
    
    do{
        
        //update data using "ctr"
        dataInput =  [ADBrokerHelpers updateDataInput:ctr
                                           fixedInput:fixedInput
                                    fixedInput_length: fixedInputLength];
        
        CCHmac(kCCHmacAlgSHA256,
               keyDerivationKey,
               keyDerivationKeyLength,
               dataInput,
               (fixedInputLength+4), //+4 to account for ctr
               cHMAC);
        
        //decide how many bytes (so the "length") copy for currently keyDerivated?
        if (256 >= outputSizeBit) {
            len = outputSizeBit;
        } else {
            len = MIN(256, outputSizeBit - numCurrentElements);
        }
        
        //convert bits in byte
        numCurrentElements_bytes = numCurrentElements/8;
        
        //copy KI in part of keyDerivated
        memcpy((keyDerivated + numCurrentElements_bytes), cHMAC, 32);
        
        //increment ctr and numCurrentElements copied in keyDerivated
        numCurrentElements = numCurrentElements + len;
        ctr++;
        
        //deallock space in memory
        free(dataInput);
        
    } while (numCurrentElements < outputSizeBit);
    
    return keyDerivated;
}


/*
 * Function used to shift data of 1 byte. This byte is the "ctr".
 */
+(uint8_t*) updateDataInput:(uint8_t) ctr
fixedInput:(uint8_t*) fixedInput
fixedInput_length:(size_t) fixedInput_length
{
    uint8_t* tmpFixedInput = (uint8_t *)malloc(fixedInput_length + 4); //+4 is caused from the ctr
    
    tmpFixedInput[0] = (ctr >> 24);
    tmpFixedInput[1] = (ctr >> 16);
    tmpFixedInput[2] = (ctr >> 8);
    tmpFixedInput[3] = ctr;
    
    memcpy(tmpFixedInput + 4, fixedInput, fixedInput_length * sizeof(uint8_t));
    return tmpFixedInput;
}



@end