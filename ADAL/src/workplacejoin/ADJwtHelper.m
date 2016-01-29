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

#import "ADJwtHelper.h"
#import "ADLogger+Internal.h"
#import "ADErrorCodes.h"
#import "NSString+ADHelperMethods.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <Security/SecKey.h>

@implementation ADJwtHelper


+ (NSString*)createSignedJWTforHeader:(NSDictionary *)header
                              payload:(NSDictionary *)payload
                           signingKey:(SecKeyRef)signingKey
{
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@", [[ADJwtHelper createJSONFromDictionary:header] adBase64UrlEncode], [[ADJwtHelper createJSONFromDictionary:payload] adBase64UrlEncode]];
    NSData* signedData = [ADJwtHelper sign:signingKey
                                      data:[signingInput dataUsingEncoding:NSUTF8StringEncoding]];
    NSString* signedEncodedDataString = [NSString Base64EncodeData: signedData];
    
    return [NSString stringWithFormat:@"%@.%@", signingInput, signedEncodedDataString];
}


+ (NSString*)decryptJWT:(NSData *)jwtData
          decrpytionKey:(SecKeyRef)decrpytionKey
{
    size_t cipherBufferSize = SecKeyGetBlockSize(decrpytionKey);
    size_t keyBufferSize = [jwtData length];
    
    NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
    OSStatus status = errSecAuthFailed;
#if TARGET_OS_IPHONE
    status = SecKeyDecrypt(decrpytionKey,
                           kSecPaddingPKCS1,
                           (const uint8_t *) [jwtData bytes],
                           cipherBufferSize,
                           [bits mutableBytes],
                           &keyBufferSize);
#else
    // TODO: SecKeyDecrypt is not available on OS X
#endif
    if(status != errSecSuccess)
    {
        return nil;
    }
    
    [bits setLength:keyBufferSize];
    return [[NSString alloc] initWithData:bits encoding:NSASCIIStringEncoding];
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
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"Could not compute SHA265 hash." errorCode:AD_ERROR_UNEXPECTED info:nil correlationId:nil];
        if (hashBytes)
            free(hashBytes);
        if (signedHashBytes)
            free(signedHashBytes);
        return nil;
    }
    OSStatus status = errSecAuthFailed;
#if TARGET_OS_IPHONE
    status = SecKeyRawSign(privateKey,
                           kSecPaddingPKCS1SHA256,
                           hashBytes,
                           hashBytesSize,
                           signedHashBytes,
                           &signedHashBytesSize);
#else
    // TODO: Use SecSignTransformCreate on OS X, SecKeyRawSign is not available on OS X
#endif
    
    [ADLogger log:ADAL_LOG_LEVEL_INFO message:@"Status returned from data signing - " errorCode:status info:nil correlationId:nil];
    signedHash = [NSData dataWithBytes:signedHashBytes
                                length:(NSUInteger)signedHashBytesSize];
    
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
    if (! jsonData) {
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:[NSString stringWithFormat:@"Got an error: %@",error] errorCode:error.code info:nil correlationId:nil];
    } else {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return nil;
}

@end
