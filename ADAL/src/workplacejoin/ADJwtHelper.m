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
    NSString* headerJSON = [ADJwtHelper JSONFromDictionary:header];
    NSString* payloadJSON = [ADJwtHelper JSONFromDictionary:payload];
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@", [headerJSON adBase64UrlEncode], [payloadJSON adBase64UrlEncode]];
    NSData* signedData = [ADJwtHelper sign:signingKey
                                      data:[signingInput dataUsingEncoding:NSUTF8StringEncoding]];
    NSString* signedEncodedDataString = [NSString adBase64UrlEncodeData: signedData];
    
    return [NSString stringWithFormat:@"%@.%@", signingInput, signedEncodedDataString];
}


+ (NSString*)decryptJWT:(NSData *)jwtData
          decrpytionKey:(SecKeyRef)decrpytionKey
{
#if TARGET_OS_IPHONE
    size_t cipherBufferSize = SecKeyGetBlockSize(decrpytionKey);
#endif // TARGET_OS_IPHONE
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
#else // !TARGET_OS_IPHONE
    (void)decrpytionKey;
    // TODO: SecKeyDecrypt is not available on OS X
#endif // TARGET_OS_IPHONE
    if(status != errSecSuccess)
    {
        return nil;
    }
    
    [bits setLength:keyBufferSize];
    return [[NSString alloc] initWithData:bits encoding:NSUTF8StringEncoding];
}


+ (NSData *)sign:(SecKeyRef)privateKey
            data:(NSData *)plainData
{
    NSData* signedHash = nil;
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = calloc(signedHashBytesSize, 1);
    if(!signedHashBytes)
    {
        return nil;
    }
    
    uint8_t* hashBytes = calloc(CC_SHA256_DIGEST_LENGTH, 1);
    if(!hashBytes)
    {
        free(signedHashBytes);
        return nil;
    }
    
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes))
    {
        [ADLogger log:ADAL_LOG_LEVEL_ERROR context:self message:@"Could not compute SHA265 hash." errorCode:AD_ERROR_UNEXPECTED info:nil correlationId:nil userInfo:nil];
        
        free(hashBytes);
        free(signedHashBytes);
        
        return nil;
    }
    OSStatus status = errSecAuthFailed;
#if TARGET_OS_IPHONE
    status = SecKeyRawSign(privateKey,
                           kSecPaddingPKCS1SHA256,
                           hashBytes,
                           CC_SHA256_DIGEST_LENGTH,
                           signedHashBytes,
                           &signedHashBytesSize);
#else
    // TODO: Use SecSignTransformCreate on OS X, SecKeyRawSign is not available on OS X
#endif
    
    if (status != errSecSuccess)
    {
        AD_LOG_ERROR(@"Failed to sign JWT", status, nil, nil);
        free(hashBytes);
        free(signedHashBytes);
        return nil;
    }

    signedHash = [NSData dataWithBytes:signedHashBytes
                                length:(NSUInteger)signedHashBytesSize];
    
    free(hashBytes);
    free(signedHashBytes);
        
    return signedHash;
}


+ (NSString *)JSONFromDictionary:(NSDictionary *)dictionary
{
    
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (!jsonData)
    {
        AD_LOG_ERROR(([NSString stringWithFormat:@"Got an error: %@", error]), error.code, nil, nil);
        return nil;
    }

    NSString* json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return json;
}

@end
