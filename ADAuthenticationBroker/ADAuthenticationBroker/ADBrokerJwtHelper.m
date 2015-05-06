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
#import "ADAuthenticationError.h"
#import "ADErrorCodes.h"
#import "ADBrokerJwtHelper.h"
#import "ADBrokerConstants.h"
#import "ADBrokerHelpers.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation ADBrokerJwtHelper

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 2048;
const uint32_t PADDING = kSecPaddingNone;

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
//
//+(NSData*) getSessionKeyFromEncryptedJWT:(NSString*) encryptedJwt
//                           privateKeyRef:(SecKeyRef) privateKeyRef
//                                   error:(NSError**) error;
//{
//    ADBrokerJWEResponse* response = [[ADBrokerJWEResponse alloc] initWithRawJWE:encryptedJwt];
//    NSData* decryptedResponse = [ADBrokerJwtHelper decryptData:response.encryptedKey
//                                                 privateKeyRef:privateKeyRef
//                                                         error:error];
//    
//    return decryptedResponse;
//}



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
                                  symmetricKey:(NSData*) symmetricKey
{
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@",
                              [[ADBrokerJwtHelper createJSONFromDictionary:header] adBase64UrlEncode],
                              [[ADBrokerJwtHelper createJSONFromDictionary:payload] adBase64UrlEncode]];
    
    NSData* derivedKey = [ADBrokerHelpers computeKDFInCounterMode:symmetricKey
                                     context:[context dataUsingEncoding:NSUTF8StringEncoding]];

    const char *cData = [signingInput cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           derivedKey.bytes,
           derivedKey.length,
           cData,
           strlen(cData),
           cHMAC);
    NSData* signedData = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString* signedEncodedDataString = [NSString Base64EncodeData: signedData];
    return [NSString stringWithFormat:@"%@.%@",
            signingInput,
            signedEncodedDataString];
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


+ (NSDictionary*) decryptJWEResponseUsingKeyDerivation:(ADBrokerJWEResponse*) encryptedResponse
                                           context:(NSData*) context
                                               key:(NSData*) rawKey
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    //char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    //bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    NSData* derivedKey = [ADBrokerHelpers computeKDFInCounterMode:rawKey
                                                          context:context];

    //[derivedKey getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [encryptedResponse.payload length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    size_t numBytesDecrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          [derivedKey bytes], kCCKeySizeAES256,
                                          [encryptedResponse.iv bytes],
                                          [encryptedResponse.payload bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);

    NSMutableDictionary* response = [NSMutableDictionary new];
    if (cryptStatus == kCCSuccess)
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        NSData* data = [NSData dataWithBytes:buffer length:numBytesDecrypted];
        free(buffer);
        
        NSError   *jsonError  = nil;
        id         jsonObject = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableLeaves error:&jsonError];
        
        if ( nil != jsonObject && [jsonObject isKindOfClass:[NSDictionary class]] )
        {
            // Load the response
            [response addEntriesFromDictionary:(NSDictionary*)jsonObject];
        }
        else
        {
            ADAuthenticationError* adError;
            if (jsonError)
            {
                adError = [ADAuthenticationError errorFromNSError:jsonError errorDetails:jsonError.localizedDescription];
            }
            else
            {
                adError = [ADAuthenticationError unexpectedInternalError:[NSString stringWithFormat:@"Unexpected object type: %@", [jsonObject class]]];
            }
            [response setObject:adError forKey:@"non_protocol_error"];
        }
        
        return response;
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end
