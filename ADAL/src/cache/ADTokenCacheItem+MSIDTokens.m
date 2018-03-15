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

#import "ADTokenCacheItem+MSIDTokens.h"
#import "ADUserInformation.h"
#import "ADUserInformation+Internal.h"
#import "MSIDAccessToken.h"
#import "MSIDRefreshToken.h"
#import "MSIDLegacySingleResourceToken.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "MSIDTokenCacheItem.h"
#import "ADTokenCacheItem+Internal.h"

@interface ADTokenCacheItem()

- (void)calculateHash;

@end

@implementation ADTokenCacheItem (MSIDTokens)

- (instancetype)initWithAccessToken:(MSIDAccessToken *)accessToken
{
    self = [self initWithBaseToken:accessToken];
    if (self)
    {
        _userInformation = [self createUserInfoWithIdToken:accessToken.idToken
                                                homeUserId:accessToken.clientInfo.userIdentifier];
        _accessTokenType = accessToken.accessTokenType;
        _accessToken = accessToken.accessToken;
        _resource = accessToken.resource;
        _expiresOn = accessToken.expiresOn;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithRefreshToken:(MSIDRefreshToken *)refreshToken
{
    self = [self initWithBaseToken:refreshToken];
    if (self)
    {
        _userInformation = [self createUserInfoWithIdToken:refreshToken.idToken
                                                homeUserId:refreshToken.clientInfo.userIdentifier];
        _refreshToken = refreshToken.refreshToken;
        _familyId = refreshToken.familyId;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithLegacySingleResourceToken:(MSIDLegacySingleResourceToken *)legacySingleResourceToken
{
    self = [self initWithAccessToken:legacySingleResourceToken];
    if (self)
    {
        _refreshToken = legacySingleResourceToken.refreshToken;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithMSIDTokenCacheItem:(MSIDTokenCacheItem *)cacheItem
{
    MSIDBaseToken *token = [cacheItem tokenWithType:cacheItem.tokenType];
    
    switch (token.tokenType) {
        case MSIDTokenTypeAccessToken:
            return [self initWithAccessToken:(MSIDAccessToken *)token];
        case MSIDTokenTypeRefreshToken:
            return [self initWithRefreshToken:(MSIDRefreshToken *)token];
        case MSIDTokenTypeLegacySingleResourceToken:
            return [self initWithLegacySingleResourceToken:(MSIDLegacySingleResourceToken *)token];
            
        default:
            return nil;
    }
}

#pragma mark - Private

- (ADUserInformation *)createUserInfoWithIdToken:(NSString *)idToken homeUserId:(NSString *)homeUserId
{
    NSError *error;
    ADUserInformation *userInformation = [ADUserInformation userInformationWithIdToken:idToken
                                                                            homeUserId:homeUserId
                                                                                 error:&error];
    if (error)
    {
        MSID_LOG_ERROR(nil, @"Failed to create user information with id token.");
    }
    
    return userInformation;
}

- (instancetype)initWithBaseToken:(MSIDBaseToken *)baseToken
{
    if (!baseToken) return nil;
    
    self = [super init];
    if (self)
    {
        _clientId = baseToken.clientId;
        _authority = baseToken.authority.absoluteString;
        _additionalServer = baseToken.additionaServerlInfo;
        _additionalClient = [baseToken.additionalClientInfo mutableCopy];
    }
    
    return self;
}

- (MSIDLegacyTokenCacheKey *)tokenCacheKey
{
    NSURL *authorityURL = [NSURL URLWithString:self.authority];
    MSIDLegacyTokenCacheKey *key = [MSIDLegacyTokenCacheKey keyWithAuthority:authorityURL
                                                                    clientId:self.clientId
                                                                    resource:self.resource
                                                                legacyUserId:self.userInformation.userId];
    
    return key;
}

- (MSIDTokenCacheItem *)tokenCacheItem
{
    MSIDTokenCacheItem *cacheItem = [MSIDTokenCacheItem new];
    cacheItem.clientId = self.clientId;
    cacheItem.oauthTokenType = self.accessTokenType;
    cacheItem.accessToken = self.accessToken;
    cacheItem.refreshToken = self.refreshToken;
    cacheItem.idToken = self.userInformation.rawIdToken;
    cacheItem.target = self.resource;
    cacheItem.expiresOn = self.expiresOn;
    cacheItem.cachedAt = nil;
    cacheItem.familyId = self.familyId;
    cacheItem.authority = [NSURL URLWithString:self.authority];
    cacheItem.uniqueUserId = self.userInformation.userId;
    cacheItem.tokenType = [MSIDTokenTypeHelpers tokenTypeWithRefreshToken:self.refreshToken accessToken:self.accessToken];
    cacheItem.additionalInfo = self.additionalServer;
    cacheItem.additionalClientInfo = self.additionalClient;
    return cacheItem;
}

@end
