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
#import "ADALHelpers.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonDigest.h>

#import "ADAL_Internal.h"
#import "ADALAuthorityUtils.h"

@implementation ADALHelpers

+ (void)removeNullStringFrom:(NSDictionary *)dict
{
    for (NSString* key in dict.allKeys)
    {
        if([[dict valueForKey:key] isEqualToString:@"(null)"])
        {
            [dict setValue:nil forKey:key];
        }
    }
}

+ (NSString *)getEndpointName:(NSString *)fullEndpoint
{
    if([NSString msidIsStringNilOrBlank:fullEndpoint])
    {
        return nil;
    }
    
    NSURL* endpointUrl = [NSURL URLWithString:fullEndpoint.lowercaseString];
    NSArray* paths = endpointUrl.pathComponents;
    if (paths.count >= 2)
    {
        return[paths objectAtIndex:[paths count]-1];
    }
    return nil;
}

+ (NSData *)convertBase64UrlStringToBase64NSData:(NSString *)base64UrlString
{
    NSString* outVal = [ADALHelpers convertBase64UrlStringToBase64NSString:base64UrlString];
    return [outVal dataUsingEncoding:NSUTF8StringEncoding];
}


+ (NSString*)convertBase64UrlStringToBase64NSString:(NSString *)base64UrlString
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

+ (NSString *)createSignedJWTUsingKeyDerivation:(NSDictionary *)header
                                        payload:(NSDictionary *)payload
                                        context:(NSString *)context
                                   symmetricKey:(NSData *)symmetricKey
{
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@",
                              [[ADALHelpers JSONFromDictionary:header] msidBase64UrlEncode],
                              [[ADALHelpers JSONFromDictionary:payload] msidBase64UrlEncode]];
    
    NSData* derivedKey = [ADALHelpers computeKDFInCounterMode:symmetricKey
                                                    context:[context dataUsingEncoding:NSUTF8StringEncoding]];
    
    NSData* data = [signingInput dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           derivedKey.bytes,
           derivedKey.length,
           [data bytes],
           [data length],
           cHMAC);
    NSData* signedData = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSString* signedEncodedDataString = [NSString msidBase64UrlEncodedStringFromData:signedData];
    return [NSString stringWithFormat:@"%@.%@",
            signingInput,
            signedEncodedDataString];
}


+ (NSString *)JSONFromDictionary:(NSDictionary *)dictionary
{
    
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (!jsonData)
    {
        return nil;
    }
    
    NSString* json = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return json;
}

+ (NSData*)computeKDFInCounterMode:(NSData *)key
                           context:(NSData *)ctx
{
    NSData* labelData = [ADAL_AAD_SECURECONVERSATION_LABEL dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* mutData = [NSMutableData new];
    [mutData appendBytes:labelData.bytes length:labelData.length];
    Byte bytes[] = {0x00};
    [mutData appendBytes:bytes length:1];
    [mutData appendBytes:ctx.bytes length:ctx.length];
    int32_t size = CFSwapInt32HostToBig(256); //make big-endian
    [mutData appendBytes:&size length:sizeof(size)];
    
    uint8_t* pbDerivedKey = [ADALHelpers KDFCounterMode:(uint8_t*)key.bytes
                                     keyDerivationKeyLength:key.length
                                                 fixedInput:(uint8_t*)mutData.bytes
                                           fixedInputLength:mutData.length];
    mutData = nil;
    NSData* returnedData = [NSData dataWithBytes:(const void *)pbDerivedKey length:32];
    free(pbDerivedKey);
    return returnedData;
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
        dataInput =  [ADALHelpers updateDataInput:ctr
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

+ (NSURL*)addClientMetadataToURL:(NSURL*)url metadata:(NSDictionary *)metadata
{
    if (!url)
    {
        return nil;
    }

    if (!metadata)
    {
        return url;
    }

    return [url msidURLWithQueryParameters:metadata];
}

+ (NSString*)addClientMetadataToURLString:(NSString*)url metadata:(NSDictionary *)metadata
{
    if (url == nil)
    {
        return nil;
    }
    
    return [[self addClientMetadataToURL:[NSURL URLWithString:url] metadata:metadata] absoluteString];
}

+ (NSString *)getUPNSuffix:(NSString *)upn
{
    if (!upn)
    {
        return nil;
    }
    
    NSArray *array = [upn componentsSeparatedByString:@"@"];
    if (array.count != 2)
    {
        return nil;
    }
    
    return array[1];
}

+ (NSString*)canonicalizeAuthority:(NSString *)authority
{
    if ([NSString msidIsStringNilOrBlank:authority])
    {
        return nil;
    }
    
    NSString* trimmedAuthority = [[authority msidTrimmedString] lowercaseString];
    NSURL* url = [NSURL URLWithString:trimmedAuthority];
    if (!url)
    {
        NSURL *authorityUrl = [NSURL URLWithString:authority];
        MSID_LOG_WARN(nil, @" The authority is not a valid URL - authority host: %@", [ADALAuthorityUtils isKnownHost:authorityUrl] ? authorityUrl.host : @"unknown host");
        MSID_LOG_WARN_PII(nil, @" The authority is not a valid URL authority: %@", authority);

        return nil;
    }
    NSString* scheme = url.scheme;
    if (![scheme isEqualToString:@"https"])
    {
        MSID_LOG_WARN(nil, @"Non HTTPS protocol for the authority");
        MSID_LOG_WARN_PII(nil, @"Non HTTPS protocol for the authority %@", authority);
        return nil;
    }
    
    url = url.absoluteURL;//Resolve any relative paths.
    NSArray* paths = url.pathComponents;//Returns '/' as the first and the tenant as the second element.
    if (paths.count < 2)
        return nil;//No path component: invalid URL
    
    NSString* tenant = [paths objectAtIndex:1];
    if ([NSString msidIsStringNilOrBlank:tenant])
    {
        return nil;
    }
    
    NSString* host = url.host;
    if ([NSString msidIsStringNilOrBlank:host])
    {
        return nil;
    }
    NSNumber* port = url.port;
    if (port != nil)
    {
        trimmedAuthority = [NSString stringWithFormat:@"%@://%@:%d/%@", scheme, host, port.intValue, tenant];
    }
    else
    {
        trimmedAuthority = [NSString stringWithFormat:@"%@://%@/%@", scheme, host, tenant];
    }
    
    return trimmedAuthority;
}

/*! Check if it is a valid authority URL.
 Returns nil if it is valid. 
 Otherwise, returns an error if the protocol is not https or the authority is not a valid URL.*/
+ (ADALAuthenticationError *)checkAuthority:(NSString *)authority
                            correlationId:(NSUUID *)correlationId
{
    NSURL* fullUrl = [NSURL URLWithString:authority.lowercaseString];
    
    ADALAuthenticationError* adError = nil;
    if (!fullUrl || ![fullUrl.scheme isEqualToString:@"https"])
    {
        adError = [ADALAuthenticationError errorFromArgument:authority argumentName:@"authority" correlationId:correlationId];
    }
    else
    {
        NSArray* paths = fullUrl.pathComponents;
        if (paths.count < 2)
        {
            adError = [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_INVALID_ARGUMENT
                                                             protocolCode:nil
                                                             errorDetails:@"Missing tenant in the authority URL. Please add the tenant or use 'common', e.g. https://login.windows.net/example.com."
                                                            correlationId:correlationId];
        }
    }
    return adError;
}

+ (NSString *)stringFromDate:(NSDate *)date
{
    static NSDateFormatter* s_dateFormatter = nil;
    static dispatch_once_t s_dateOnce;
    
    dispatch_once(&s_dateOnce, ^{
        s_dateFormatter = [[NSDateFormatter alloc] init];
        [s_dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
        [s_dateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss.SSSS"];
    });
    
    return [s_dateFormatter stringFromDate:date];
}

+ (NSString *)normalizeUserId:(NSString *)userId
{
    if (!userId)
    {
        return nil;//Quick exit;
    }
    NSString* normalized = [userId msidTrimmedString].lowercaseString;
    
    return normalized.length ? normalized : nil;
}

@end
