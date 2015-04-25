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

#import <Foundation/Foundation.h>

@interface ADHelpers : NSObject

+(BOOL) isADFSInstance:(NSString*) endpoint;

+(BOOL) isADFSInstanceURL:(NSURL*) endpointUrl;

+(NSString*) getEndpointName:(NSString*) fullEndpoint;

+ (NSData*) convertBase64UrlStringToBase64NSData:(NSString*) base64UrlString;

+ (NSString*) convertBase64UrlStringToBase64NSString:(NSString*) base64UrlString;

+(NSString*) createSignedJWTUsingKeyDerivation:(NSDictionary*) header
                                       payload:(NSDictionary*) payload
                                       context:(NSString*) context
                                  symmetricKey:(NSData*) symmetricKey;

+ (NSString *) createJSONFromDictionary:(NSDictionary *) dictionary;

+ (NSData*) computeKDFInCounterMode:(NSData*)key
                            context:(NSData*)ctx;

@end