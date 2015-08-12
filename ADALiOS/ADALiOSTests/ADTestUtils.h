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

@class ADProfileInfo;
@class ADTokenCacheStoreItem;

@interface ADTestUtils : NSObject

@property NSString* username;
@property NSString* friendlyName;
@property NSString* subject;
@property NSString* tid;
@property NSString* profileVersion;
@property NSString* extra_claim;

@property NSString* authority;
@property NSString* clientId;
@property NSString* accessToken;
@property NSString* accessTokenType;
@property NSString* refreshToken;
@property NSArray* scopes;
@property NSDate* expiresOn;

+ (ADTestUtils*)defaultUtils;

- (NSString*)rawProfileInfo;
- (ADProfileInfo*)createProfileInfo:(NSString* __autoreleasing *)errorDetails;
- (ADTokenCacheStoreItem*)createCacheItem:(NSString* __autoreleasing *)errorDetails;


@end
