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

#import "ADALTokenCacheItem+MSIDTokens.h"
#import "ADALUserInformation.h"
#import "ADALUserInformation+Internal.h"
#import "MSIDLegacyAccessToken.h"
#import "MSIDLegacyRefreshToken.h"
#import "MSIDLegacySingleResourceToken.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "ADALTokenCacheItem+Internal.h"
#import "MSIDLegacyTokenCacheItem.h"
#import "NSURL+MSIDExtensions.h"
#import "MSIDAccountIdentifier.h"
#import "MSIDAuthority.h"

@interface ADALTokenCacheItem()

- (void)calculateHash;

@end

@implementation ADALTokenCacheItem (MSIDTokens)

- (instancetype)initWithLegacyAccessToken:(MSIDLegacyAccessToken *)accessToken
{
    self = [self initWithBaseToken:accessToken];
    if (self)
    {
        _userInformation = [self createUserInfoWithIdToken:accessToken.idToken
                                             homeAccountId:accessToken.accountIdentifier.homeAccountId];
        _accessTokenType = accessToken.accessTokenType;
        _accessToken = accessToken.accessToken;
        _resource = accessToken.resource;
        _expiresOn = accessToken.expiresOn;
        _enrollmentId = accessToken.enrollmentId;
        _applicationIdentifier = accessToken.applicationIdentifier;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithLegacyRefreshToken:(MSIDLegacyRefreshToken *)refreshToken
{
    self = [self initWithBaseToken:refreshToken];
    if (self)
    {
        _userInformation = [self createUserInfoWithIdToken:refreshToken.idToken
                                             homeAccountId:refreshToken.accountIdentifier.homeAccountId];

        _refreshToken = refreshToken.refreshToken;
        _familyId = refreshToken.familyId;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithLegacySingleResourceToken:(MSIDLegacySingleResourceToken *)legacySingleResourceToken
{
    self = [self initWithLegacyAccessToken:legacySingleResourceToken];
    if (self)
    {
        _refreshToken = legacySingleResourceToken.refreshToken;
        _familyId = legacySingleResourceToken.familyId;
    }
    
    [self calculateHash];
    
    return self;
}

- (instancetype)initWithMSIDLegacyTokenCacheItem:(MSIDLegacyTokenCacheItem *)cacheItem
{
    MSIDBaseToken *token = [cacheItem tokenWithType:cacheItem.credentialType];
    
    switch (token.credentialType) {
        case MSIDAccessTokenType:
            return [self initWithLegacyAccessToken:(MSIDLegacyAccessToken *)token];
        case MSIDRefreshTokenType:
            return [self initWithLegacyRefreshToken:(MSIDLegacyRefreshToken *)token];
        case MSIDLegacySingleResourceTokenType:
            return [self initWithLegacySingleResourceToken:(MSIDLegacySingleResourceToken *)token];
            
        default:
            return nil;
    }
}

#pragma mark - Private

- (ADALUserInformation *)createUserInfoWithIdToken:(NSString *)idToken homeAccountId:(NSString *)homeAccountId
{
    NSError *error;
    ADALUserInformation *userInformation = [ADALUserInformation userInformationWithIdToken:idToken
                                                                         homeAccountId:homeAccountId
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
        _authority = baseToken.authority.url.absoluteString;
        _storageAuthority = baseToken.storageAuthority.url.absoluteString;
        _additionalServer = baseToken.additionalServerInfo;
    }
    
    return self;
}

- (MSIDLegacyTokenCacheKey *)tokenCacheKey
{
    NSURL *authorityURL = [NSURL URLWithString:self.storageAuthority ? self.storageAuthority : self.authority];

    MSIDLegacyTokenCacheKey *key = [[MSIDLegacyTokenCacheKey alloc] initWithAuthority:authorityURL
                                                                             clientId:self.clientId
                                                                             resource:self.resource
                                                                         legacyUserId:self.userInformation.userId];
    
    key.applicationIdentifier = self.applicationIdentifier;
    return key;
}

- (MSIDLegacyTokenCacheItem *)tokenCacheItem
{
    MSIDLegacyTokenCacheItem *cacheItem = [MSIDLegacyTokenCacheItem new];
    cacheItem.clientId = self.clientId;
    cacheItem.oauthTokenType = self.accessTokenType;
    cacheItem.accessToken = self.accessToken;
    cacheItem.refreshToken = self.refreshToken;
    cacheItem.secret = self.accessToken ? self.accessToken : self.refreshToken;
    cacheItem.idToken = self.userInformation.rawIdToken;
    cacheItem.target = self.resource;
    cacheItem.expiresOn = self.expiresOn;
    cacheItem.cachedAt = nil;
    cacheItem.familyId = self.familyId;
    cacheItem.authority = [NSURL URLWithString:self.authority];
    cacheItem.environment = cacheItem.authority.msidHostWithPortIfNecessary;
    cacheItem.realm = cacheItem.authority.msidTenant;
    cacheItem.homeAccountId = self.userInformation.homeAccountId;
    cacheItem.credentialType = [MSIDCredentialTypeHelpers credentialTypeWithRefreshToken:self.refreshToken accessToken:self.accessToken];
    cacheItem.additionalInfo = self.additionalServer;
    cacheItem.enrollmentId = self.enrollmentId;
    cacheItem.applicationIdentifier = self.applicationIdentifier;
    return cacheItem;
}

@end
