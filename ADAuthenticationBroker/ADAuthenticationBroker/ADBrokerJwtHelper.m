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

@implementation ADBrokerJwtHelper

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 2048;
const uint32_t PADDING = kSecPaddingNone;

+(NSDictionary*) decryptJWE:(NSString*) encryptedJwt
              privateKeyRef:(SecKeyRef) privateKeyRef
                      error:(NSError**) error
{
    encryptedJwt = [encryptedJwt adBase64UrlDecode];
    NSDictionary* resultDictionary = [NSDictionary new];
    NSData* decryptedeResponse = [ADBrokerJwtHelper decryptData:encryptedJwt
                                                  privateKeyRef:privateKeyRef
                                                          error:error];
    
    if(!error)
    {
        id         jsonObject = [NSJSONSerialization JSONObjectWithData:decryptedeResponse options:0 error:error];
        
        if ( nil != jsonObject && [jsonObject isKindOfClass:[NSDictionary class]] )
        {
            resultDictionary = (NSDictionary*)jsonObject;
        }
        else
        {
            if (!error)
            {
                *error = [NSError errorWithDomain:BROKER_ERROR_DOMAIN
                                              code:kCFErrorHTTPParseFailure
                                          userInfo:@{
                                                     NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unexpected object type instead of JWE: %@", [jsonObject class]]
                                                     }];
            }
        }
    }
    return resultDictionary;
}


+(NSData*) decryptData:(NSString*) encryptedJwt
         privateKeyRef:(SecKeyRef) privateKeyRef
                 error:(NSError**) error
{
    size_t plainBufferSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *plainBuffer = malloc(plainBufferSize);
    NSData *incomingData = [encryptedJwt dataUsingEncoding:NSASCIIStringEncoding];
    uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKeyRef);
    OSStatus status = SecKeyDecrypt(privateKeyRef,
                                    kSecPaddingOAEP,
                                    cipherBuffer,
                                    cipherBufferSize,
                                    plainBuffer,
                                    &plainBufferSize);
    
    if(status != errSecSuccess) {
        
        return nil;
    }
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    return decryptedData;
}

@end
