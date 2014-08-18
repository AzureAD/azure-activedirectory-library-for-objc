//
//  ADPkeyAuthHelper.m
//  ADALiOS
//
//  Created by Kanishk Panwar on 7/29/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import "ADPkeyAuthHelper.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "RegistrationInformation.h"
#import "NSString+ADHelperMethods.h"
#import "WorkPlaceJoin.h"
#import "NSData+ADHelperMethods.h"
#import "OpenSSLHelper.h"

@implementation ADPkeyAuthHelper



+ (NSString*) createDeviceAuthResponse:(NSString*) authorizationServer
                    challengeData:(NSMutableDictionary*) challengeData
{
    RegistrationInformation *info = [[WorkPlaceJoin WorkPlaceJoinManager] getRegistrationInformation];
    NSString* authHeaderTemplate = @"PKeyAuth %@ Context=\"%@\", Version=\"%@\"";
    NSString* pKeyAuthHeader = @"";
    
    NSString* certAuths = [challengeData valueForKey:@"CertAuthorities"];
    certAuths = [certAuths adUrlFormDecode];
    
    NSString* certIssuer = [OpenSSLHelper getCertificateIssuer:[info certificateData]];
    
    if([info isWorkPlaceJoined]){
        pKeyAuthHeader = [NSString stringWithFormat:@"AuthToken=\"%@\",", [ADPkeyAuthHelper createDeviceAuthResponse:authorizationServer nonce:[challengeData valueForKey:@"nonce"] identity:info]];
    }
    [info releaseData];
    return [NSString stringWithFormat:authHeaderTemplate, pKeyAuthHeader,[challengeData valueForKey:@"Context"],  [challengeData valueForKey:@"Version"]];
}



+ (NSString *) createDeviceAuthResponse:(NSString*) audience
                                  nonce:(NSString*) nonce
                               identity:(RegistrationInformation *) identity{
    
    
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
    NSString* signedEncodedDataString = [signedData adBase64EncodeData];
    
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
    assert(status == noErr);
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
        NSLog(@"Got an error: %@", error);
    } else {
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    }
    return nil;
}

@end
