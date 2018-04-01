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
    
    return self;
}

- (instancetype)initWithLegacySingleResourceToken:(MSIDLegacySingleResourceToken *)legacySingleResourceToken
{
    self = [self initWithAccessToken:legacySingleResourceToken];
    if (self)
    {
        _refreshToken = legacySingleResourceToken.refreshToken;
    }
    
    return self;
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
    self = [super init];
    if (self)
    {
        _clientId = baseToken.clientId;
        _authority = baseToken.authority.absoluteString;
        _additionalServer = baseToken.additionaServerlInfo;
        _additionalClient = [NSMutableDictionary new];
    }
    
    return self;
}

@end
