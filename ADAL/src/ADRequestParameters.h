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

#import "ADTokenCacheDataSource.h"
#import "MSIDRequestContext.h"
#import "MSIDWorkPlaceJoinConstants.h"
#import <WebKit/WebKit.h>

@class MSIDConfiguration;
@class MSIDAccountIdentifier;

@interface ADRequestParameters : NSObject <MSIDRequestContext>

@property (retain, nonatomic) NSString *authority;
@property (retain, nonatomic) NSString *cloudAuthority;
@property (retain, nonatomic) NSString *resource;
@property (retain, nonatomic) NSString *clientId;
@property (retain, nonatomic) NSString *redirectUri;
@property (retain, nonatomic) NSString *scopesString;
@property (retain, nonatomic) ADUserIdentifier *identifier;
@property (retain, nonatomic) NSDictionary* decodedClaims;
@property (retain, nonatomic) NSArray<NSString *>* clientCapabilities;
@property (retain, nonatomic) NSString *extraQueryParameters;
@property BOOL extendedLifetime;
@property BOOL forceRefresh;
@property (retain, nonatomic) NSUUID *correlationId;
@property (retain, nonatomic) NSString *telemetryRequestId;
@property (retain, nonatomic) NSString *logComponent;
@property (retain, nonatomic) MSIDAccountIdentifier *account;
@property (retain, nonatomic) NSDictionary *appRequestMetadata;

- (NSString *)openIdScopesString;
- (MSIDConfiguration *)msidConfig;

- (BOOL)isCapableForMAMCA;
+ (NSString *)applicationIdentifierWithAuthority:(NSString *)authority;

- (NSString *)enrollmentIDForHomeAccountID:(NSString *)homeAccountId
                              legacyUserID:(NSString *)legacyUserID;

#if TARGET_OS_IPHONE && !MSID_EXCLUDE_WEBKIT

+ (WKWebViewConfiguration *)createWebViewConfigWithPKeyAuthUserAgent;

#endif


@end
