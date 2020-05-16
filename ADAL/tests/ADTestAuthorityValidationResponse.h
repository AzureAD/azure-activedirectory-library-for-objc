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

@class ADTestURLResponse;

@interface ADTestAuthorityValidationResponse : NSObject

+ (ADTestURLResponse*)validAuthority:(NSString *)authority;
+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                         withMetadata:(NSArray *)metadata;

+ (ADTestURLResponse *)validAuthority:(NSString *)authority
                          trustedHost:(NSString *)trustedHost
                         withMetadata:(NSArray *)metadata;

+ (ADTestURLResponse *)invalidAuthority:(NSString *)authority validationEnabled:(BOOL)validationEnabled;
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
