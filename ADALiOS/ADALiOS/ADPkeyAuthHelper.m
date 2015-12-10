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

#import "ADPkeyAuthHelper.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "RegistrationInformation.h"
#import "NSString+ADHelperMethods.h"
#import "WorkPlaceJoin.h"
#import "ADLogger.h"
#import "ADErrorCodes.h"

#if TARGET_OS_IPHONE
@implementation ADPkeyAuthHelper

+ (NSString*) computeThumbprint:(NSData*) data{
    return [ADPkeyAuthHelper computeThumbprint:data isSha2:NO];
}


+ (NSString*) computeThumbprint:(NSData*) data isSha2:(BOOL) isSha2
{
    int length = CC_SHA1_DIGEST_LENGTH;
    if(isSha2){
        length = CC_SHA256_DIGEST_LENGTH;
    }
    
    unsigned char dataBuffer[length];
    if(!isSha2){
        CC_SHA1(data.bytes, (CC_LONG)data.length, dataBuffer);
    }
    else{
        CC_SHA256(data.bytes, (CC_LONG)data.length, dataBuffer);
    }
    
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:length * 3];
    for (int i = 0; i < length; ++i)
    {
        [fingerprint appendFormat:@"%02x ",dataBuffer[i]];
    }
    
    NSString* thumbprint = [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    thumbprint = [thumbprint uppercaseString];
    return [thumbprint stringByReplacingOccurrencesOfString:@" " withString:@""];
}

+ (NSString*)createDeviceAuthResponse:(NSString*)authorizationServer
                        challengeData:(NSDictionary*) challengeData
{
#if TARGET_OS_IPHONE
    RegistrationInformation *info = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation];
    if (![info isWorkPlaceJoined])
    {
        AD_LOG_ERROR(@"Attempting to create device auth response while not workplace joined.", AD_ERROR_WPJ_REQUIRED, nil);
        return nil;
    }
    NSString* certAuths = [challengeData valueForKey:@"CertAuthorities"];
    
    if (certAuths)
    {
        certAuths = [[certAuths adUrlFormDecode] stringByReplacingOccurrencesOfString:@" "
                                                                           withString:@""];
        NSString* issuerOU = [ADPkeyAuthHelper getOrgUnitFromIssuer:[info certificateIssuer]];
        if (![self isValidIssuer:certAuths keychainCertIssuer:issuerOU])
        {
            AD_LOG_ERROR(@"Certificate Authority specified by device auth request does not match certificate in keychain.", AD_ERROR_WPJ_REQUIRED, nil);
            return nil;
        }
    }
    else if ([challengeData valueForKey:@"CertThumbprint"])
    {
        NSString* expectedThumbprint = [challengeData valueForKey:@"CertThumbprint"];
        if (![NSString adSame:expectedThumbprint toString:[ADPkeyAuthHelper computeThumbprint:[info certificateData]]])
        {
            AD_LOG_ERROR(@"Certificate Thumbprint does not match certificate in keychain.", AD_ERROR_WPJ_REQUIRED, nil);
            return nil;
        }
    }
    
    
    NSString* pKeyAuthHeader = [NSString stringWithFormat:@"AuthToken=\"%@\",", [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer nonce:[challengeData valueForKey:@"nonce"] identity:info]];
    
    [info releaseData];
    info = nil;
    return [NSString stringWithFormat:@"PKeyAuth %@ Context=\"%@\", Version=\"%@\"", pKeyAuthHeader,[challengeData valueForKey:@"Context"],  [challengeData valueForKey:@"Version"]];
#else
    return nil;
#endif
}


+ (NSString*) getOrgUnitFromIssuer:(NSString*) issuer{
    NSString *regexString = @"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}";
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:regexString options:0 error:NULL];
    
    for (NSTextCheckingResult* myMatch in [regex matchesInString:issuer options:0 range:NSMakeRange(0, [issuer length])]){
        if (myMatch.numberOfRanges > 0) {
            NSRange matchedRange = [myMatch rangeAtIndex: 0];
            return [NSString stringWithFormat:@"OU=%@", [issuer substringWithRange: matchedRange]];
        }
    }
    
    return nil;
}

+ (BOOL) isValidIssuer:(NSString*) certAuths
    keychainCertIssuer:(NSString*) keychainCertIssuer{
    NSString *regexString = @"OU=[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}";
    keychainCertIssuer = [keychainCertIssuer uppercaseString];
    certAuths = [certAuths uppercaseString];
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:regexString options:0 error:NULL];
    
    for (NSTextCheckingResult* myMatch in [regex matchesInString:certAuths options:0 range:NSMakeRange(0, [certAuths length])]){
        for (NSUInteger i = 0; i < myMatch.numberOfRanges; ++i)
        {
            NSRange matchedRange = [myMatch rangeAtIndex: i];
            NSString *text = [certAuths substringWithRange:matchedRange];
            if([NSString adSame:text toString:keychainCertIssuer]){
                return true;
            }
        }
    }
    
    return false;
}

+ (NSString *) createDeviceAuthResponse:(NSString*) audience
                                  nonce:(NSString*) nonce
                               identity:(RegistrationInformation *) identity{
    
#ifdef TARGET_OS_IPHONE
    NSArray *arrayOfStrings = @[[NSString stringWithFormat:@"%@", [[identity certificateData] base64EncodedStringWithOptions:0]]];
    NSDictionary *header = @{
                             @"alg" : @"RS256",
                             @"typ" : @"JWT",
                             @"x5c" : arrayOfStrings
                             };
    
    NSDictionary *payload = @{
                              @"aud" : audience,
                              @"nonce" : nonce,
                              @"iat" : [NSString stringWithFormat:@"%d", (CC_LONG)[[NSDate date] timeIntervalSince1970]]
                              };
    
    NSString* signingInput = [NSString stringWithFormat:@"%@.%@", [[self createJSONFromDictionary:header] adBase64UrlEncode], [[self createJSONFromDictionary:payload] adBase64UrlEncode]];
    NSData* signedData = [self sign:[identity privateKey] data:[signingInput dataUsingEncoding:NSUTF8StringEncoding]];
    NSString* signedEncodedDataString = [NSString Base64EncodeData: signedData];
    
    return [NSString stringWithFormat:@"%@.%@", signingInput, signedEncodedDataString];
#else
    return nil;
#endif
}

+ (NSData *)sign:(SecKeyRef) privateKey
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
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"Could not compute SHA265 hash." errorCode:AD_ERROR_UNEXPECTED info:nil ];
        if (hashBytes)
            free(hashBytes);
        if (signedHashBytes)
            free(signedHashBytes);
        return nil;
    }
    
#if TARGET_OS_IPHONE
    OSStatus status = SecKeyRawSign(privateKey,
                                    kSecPaddingPKCS1SHA256,
                                    hashBytes,
                                    hashBytesSize,
                                    signedHashBytes,
                                    &signedHashBytesSize);
    
    [ADLogger log:ADAL_LOG_LEVEL_INFO message:@"Status returned from data signing - " errorCode:status info:nil ];
    signedHash = [NSData dataWithBytes:signedHashBytes
                                length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes) {
        free(hashBytes);
    }
    if (signedHashBytes) {
        free(signedHashBytes);
    }
    
    return signedHash;
#else
    
    //    CFErrorRef error = nil;
    //    SecTransformRef signingTransform = SecSignTransformCreate(privateKey, &error);
    //    if (signingTransform == NULL)
    //        return NULL;
    //
    //    Boolean success = SecTransformSetAttribute(signingTransform, kSecDigestTypeAttribute, kSecDigestSHA2, &error);
    //
    //    if (success) {
    //        success = SecTransformSetAttribute(signingTransform,
    //                                           kSecTransformInputAttributeName,
    //                                           hashBytes,
    //                                           &error) != false;
    //    }
    //    if (!success) {
    //        CFRelease(signingTransform);
    //        return NULL;
    //    }
    //
    //    CFDataRef signature = SecTransformExecute(signingTransform, &error);
    //    CFRetain(signature);
    //    signedHash = (__bridge id)signature;
    //    CFRelease(signingTransform);
    //    CFRelease(signature);
    
#endif
    if (hashBytes) {
        free(hashBytes);
    }
    if (signedHashBytes) {
        free(signedHashBytes);
    }
    return nil;
}

+ (NSString *) createJSONFromDictionary:(NSDictionary *) dictionary{
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dictionary
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    NSString* returnValue = nil;
    if (! jsonData) {
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:[NSString stringWithFormat:@"Got an error: %@",error] errorCode:error.code info:nil ];
    } else {
        returnValue = SAFE_ARC_AUTORELEASE([[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding]);
    }
    return returnValue;
}

@end
#endif
