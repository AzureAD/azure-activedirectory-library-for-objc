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

@interface IPAuthorization : NSObject <NSCoding>

+ (NSString *)cacheKeyForServer:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope;
+ (NSString *)normalizeAuthorizationServer:(NSString *)authorizationServer;

@property (strong, readonly, nonatomic) NSString *authorizationServer;
@property (strong, readonly, nonatomic) NSString *resource;
@property (strong, readonly, nonatomic) NSString *scope;
@property (strong, readonly, nonatomic) NSString *cacheKey;

@property (strong) NSString *accessToken;
@property (strong) NSString *accessTokenType;
@property (strong) NSDate   *expires;
@property (strong) NSString *code;
@property (strong) NSString *refreshToken;

- (id)initWithServer:(NSString *)authorizationServer resource:(NSString *)resource scope:(NSString *)scope;

- (BOOL)isExpired;
- (BOOL)isRefreshable;

@end
