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

@interface ADALHelpers : NSObject

+ (NSString *)getEndpointName:(NSString *)fullEndpoint;

+ (NSData *)convertBase64UrlStringToBase64NSData:(NSString *)base64UrlString;
+ (NSString *)convertBase64UrlStringToBase64NSString:(NSString *)base64UrlString;

+ (NSString *)createSignedJWTUsingKeyDerivation:(NSDictionary *)header
                                        payload:(NSDictionary *)payload
                                        context:(NSString *)context
                                   symmetricKey:(NSData *)symmetricKey;

+ (NSString *)JSONFromDictionary:(NSDictionary *)dictionary;

+ (NSData*)computeKDFInCounterMode:(NSData *)key
                           context:(NSData *)ctx;

+ (void)removeNullStringFrom:(NSDictionary *)dict;

+ (NSURL *)addClientMetadataToURL:(NSURL*)url metadata:(NSDictionary *)metadata;
+ (NSString *)addClientMetadataToURLString:(NSString*)url metadata:(NSDictionary *)metadata;

+ (NSString *)getUPNSuffix:(NSString *)upn;

/*! Takes the string and makes it canonical URL, e.g. lowercase with
 ending trailing "/". If the authority is not a valid URL, the method
 will return nil. */
+ (NSString *)canonicalizeAuthority:(NSString *)authority;

+ (ADALAuthenticationError *)checkAuthority:(NSString *)authority
                            correlationId:(NSUUID *)correlationId;

+ (NSString *)stringFromDate:(NSDate *)date;

+ (NSString *)normalizeUserId:(NSString *)userId;

@end
