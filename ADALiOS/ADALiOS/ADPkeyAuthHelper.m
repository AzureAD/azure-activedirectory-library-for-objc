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

+ (NSString*) createDeviceAuthResponse:(NSString*) authorizationServer
                         challengeData:(NSDictionary*) challengeData
{
    ADRegistrationInformation *info = [[ADWorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation];
    NSString* authHeaderTemplate = @"PKeyAuth %@ Context=\"%@\", Version=\"%@\"";
    NSString* pKeyAuthHeader = @"";
    
    NSString* certAuths = [challengeData valueForKey:@"CertAuthorities"];
    certAuths = [[certAuths adUrlFormDecode] stringByReplacingOccurrencesOfString:@" "
                                                                       withString:@""];
    
    //NSMutableSet* certIssuer = [self getCertIssuer:[info certificate]];
    NSString* certIssuer = [NSString stringWithFormat:@"OU=%@", [info certificateSubject]];
    if([info isWorkPlaceJoined] && [self isValidIssuer:certAuths keychainCertIssuer:certIssuer]){
        pKeyAuthHeader = [NSString stringWithFormat:@"AuthToken=\"%@\",", [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer nonce:[challengeData valueForKey:@"nonce"] identity:info]];
    }
    
    [info releaseData];
    info = nil;
    return [NSString stringWithFormat:authHeaderTemplate, pKeyAuthHeader,[challengeData valueForKey:@"Context"],  [challengeData valueForKey:@"Version"]];
}

+ (BOOL) isValidIssuer:(NSString*) certAuths
    keychainCertIssuer:(NSString*) keychainCertIssuer{
    
    NSArray * acceptedCerts = [certAuths componentsSeparatedByString:@";"];
    for (int i=0; i<[acceptedCerts count]; i++) {
        NSArray * keyPair = [[acceptedCerts objectAtIndex:i] componentsSeparatedByString:@","];
        for(int index=0;index<[keyPair count]; index++){
            if([[keyPair objectAtIndex:index] caseInsensitiveCompare:keychainCertIssuer]==NSOrderedSame){
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
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
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
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
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


//+(NSMutableSet*) getCertIssuer: (SecCertificateRef) certificate
//{
//    NSString* string = (__bridge NSString *)(SecCertificateCopySubjectSummary(certificate)) ;
//    NSMutableSet* returnedSet = [[NSMutableSet alloc] init];
//    NSRegularExpression *nameExpression = [NSRegularExpression regularExpressionWithPattern:@"Issuer: (.*?)\n" options:NSRegularExpressionSearch error:nil];
//    
//    NSArray *matches = [nameExpression matchesInString:string
//                                               options:0
//                                                 range:NSMakeRange(0, [string length])];
//    if(matches){
//        NSTextCheckingResult *match = [matches objectAtIndex:0];
//        NSRange matchRange = [match range];
//        NSString *matchString = [string substringWithRange:matchRange];
//        matchString = [matchString substringFromIndex:8];
//        NSArray * issuerParts = [matchString componentsSeparatedByString:@","];
//        for (int i=0; i<[issuerParts count]; i++) {
//            [returnedSet addObject: [[issuerParts objectAtIndex:i] stringByReplacingOccurrencesOfString:@" "
//                                                                                             withString:@""]];
//        }
//        
//    }
//    CFRelease((__bridge CFTypeRef)(string));
//    return returnedSet;
//}
//



@end
