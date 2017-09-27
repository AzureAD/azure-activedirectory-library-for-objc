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

@class ADTestURLResponse;

@interface ADTestAuthorityValidationResponse : NSObject

+ (ADTestURLResponse*)validAuthority:(NSString *)authority;
+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                         withMetadata:(NSArray *)metadata;
+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                          trustedHost:(NSString *)trustedHost
                         withMetadata:(NSArray *)metadata;

+ (ADTestURLResponse*)invalidAuthority:(NSString *)authority;
+ (ADTestURLResponse*)invalidAuthority:(NSString *)authority
                           trustedHost:(NSString *)trustedHost;

+ (ADTestURLResponse*)validDrsPayload:(NSString *)domain
                              onPrems:(BOOL)onPrems
        passiveAuthenticationEndpoint:(NSString *)passiveAuthEndpoint;
+ (ADTestURLResponse*)invalidDrsPayload:(NSString *)domain
                                onPrems:(BOOL)onPrems;
+ (ADTestURLResponse*)unreachableDrsService:(NSString *)domain
                                   onPrems:(BOOL)onPrems;
+ (ADTestURLResponse*)validWebFinger:(NSString *)passiveEndpoint
                           authority:(NSString *)authority;
+ (ADTestURLResponse*)invalidWebFinger:(NSString *)passiveEndpoint
                             authority:(NSString *)authority;
+ (ADTestURLResponse*)invalidWebFingerNotTrusted:(NSString *)passiveEndpoint
                                       authority:(NSString *)authority;
+ (ADTestURLResponse*)unreachableWebFinger:(NSString *)passiveEndpoint
                                 authority:(NSString *)authority;

@end
