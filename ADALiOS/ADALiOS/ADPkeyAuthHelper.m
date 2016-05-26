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
#import "ADRegistrationInformation.h"
#import "NSString+ADHelperMethods.h"
#import "ADWorkPlaceJoin.h"
#import "ADLogger.h"
#import "ADErrorCodes.h"

@implementation ADPkeyAuthHelper

+ (NSString*) computeThumbprint:(NSData*) data{
    return [ADPkeyAuthHelper computeThumbprint:data isSha2:NO];
}


+ (NSString*) computeThumbprint:(NSData*) data isSha2:(BOOL) isSha2{
    
    //compute SHA-1 thumbprint
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


+ (nonnull NSString*)createDeviceAuthResponse:(NSString*)authorizationServer
                                challengeData:(NSDictionary*) challengeData
{
    ADRegistrationInformation *info = [[ADWorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation];
    
    if (!challengeData)
    {
        // Error should have been logged before this where there is more information on why the challenge data was bad
    }
    else if (![info isWorkPlaceJoined])
    {
        AD_LOG_INFO(@"PKeyAuth: Received PKeyAuth request but no WPJ info.", nil);
    }
    else
    {
        NSString* certAuths = [challengeData valueForKey:@"CertAuthorities"];
        NSString* expectedThumbprint = [challengeData valueForKey:@"CertThumbprint"];
        
        if (certAuths)
        {
            NSString* issuerOU = [ADPkeyAuthHelper getOrgUnitFromIssuer:[info certificateIssuer]];
            if (![self isValidIssuer:certAuths keychainCertIssuer:issuerOU])
            {
                AD_LOG_ERROR(@"PKeyAuth Error: Certificate Authority specified by device auth request does not match certificate in keychain.", AD_ERROR_WPJ_REQUIRED, nil);
                [info releaseData];
                info = nil;
            }
        }
        else if (expectedThumbprint)
        {
            if (![NSString adSame:expectedThumbprint toString:[ADPkeyAuthHelper computeThumbprint:[info certificateData]]])
            {
                AD_LOG_ERROR(@"PKeyAuth Error: Certificate Thumbprint does not match certificate in keychain.", AD_ERROR_WPJ_REQUIRED, nil);
                [info releaseData];
                info = nil;
            }
        }
    }
    
    NSString* pKeyAuthHeader = @"";
    if (info)
    {
        pKeyAuthHeader = [NSString stringWithFormat:@"AuthToken=\"%@\",", [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer nonce:[challengeData valueForKey:@"nonce"] identity:info]];
        
        [info releaseData];
        info = nil;
    }
    
    return [NSString stringWithFormat:@"PKeyAuth %@ Context=\"%@\", Version=\"%@\"", pKeyAuthHeader,[challengeData valueForKey:@"Context"],  [challengeData valueForKey:@"Version"]];
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
                               identity:(ADRegistrationInformation *) identity{
    
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
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:@"Could not compute SHA265 hash." errorCode:AD_ERROR_UNEXPECTED additionalInformation:nil ];
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
    
    [ADLogger log:ADAL_LOG_LEVEL_INFO message:@"Status returned from data signing - " errorCode:status additionalInformation:nil ];
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
        [ADLogger log:ADAL_LOG_LEVEL_ERROR message:[NSString stringWithFormat:@"Got an error: %@",error] errorCode:error.code additionalInformation:nil ];
    } else {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return nil;
}

@end
