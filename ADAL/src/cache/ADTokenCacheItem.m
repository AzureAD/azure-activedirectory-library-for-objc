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

#import "ADAL_Internal.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheKey.h"

@implementation ADTokenCacheItem

@synthesize accessToken = _accessToken;
@synthesize accessTokenType = _accessTokenType;
@synthesize expiresOn = _expiresOn;
@synthesize refreshToken = _refreshToken;
@synthesize sessionKey = _sessionKey;
@synthesize familyId = _familyId;

- (NSUInteger)hash
{
    return _hash;
}

- (void)calculateHash
{
    _hash = [[NSString stringWithFormat:@"%@%@%@%@", _resource, _authority, _clientId, _userInformation.userId] hash];
}

//Multi-resource refresh tokens are stored separately, as they apply to all resources. As such,
//we create a special, "broad" cache item, with nil resource and access token:
- (BOOL)isMultiResourceRefreshToken
{
    return [NSString adIsStringNilOrBlank:_resource]
        && [NSString adIsStringNilOrBlank:_accessToken]
       && ![NSString adIsStringNilOrBlank:_refreshToken];
}

- (id)copyWithZone:(NSZone*) zone
{
    ADTokenCacheItem* item = [[ADTokenCacheItem allocWithZone:zone] init];
    
    item->_resource = [_resource copyWithZone:zone];
    item->_authority = [_authority copyWithZone:zone];
    item->_clientId = [_clientId copyWithZone:zone];
	item->_familyId = [_familyId copyWithZone:zone];
    item->_accessToken = [_accessToken copyWithZone:zone];
    item->_accessTokenType = [_accessTokenType copyWithZone:zone];
    item->_refreshToken = [_refreshToken copyWithZone:zone];
    item->_expiresOn = [_expiresOn copyWithZone:zone];
    item->_userInformation = [_userInformation copyWithZone:zone];
    item->_sessionKey = [_sessionKey copyWithZone:zone];
	item->_tombstone = [_tombstone mutableCopyWithZone:zone];
    
    [item calculateHash];
    
    return item;
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_resource);
    SAFE_ARC_RELEASE(_authority);
    SAFE_ARC_RELEASE(_clientId);
    SAFE_ARC_RELEASE(_accessToken);
    SAFE_ARC_RELEASE(_accessTokenType);
    SAFE_ARC_RELEASE(_refreshToken);
    SAFE_ARC_RELEASE(_expiresOn);
    SAFE_ARC_RELEASE(_userInformation);
    SAFE_ARC_RELEASE(_sessionKey);
    
    SAFE_ARC_SUPER_DEALLOC();
}

- (ADTokenCacheKey*)extractKey:(ADAuthenticationError* __autoreleasing *)error
{
    return [ADTokenCacheKey keyWithAuthority:_authority
                                         resource:_resource
                                         clientId:_clientId
                                            error:error];
}

- (BOOL)isExpired
{
    if (nil == _expiresOn)
    {
        return NO;//Assume opportunistically that it is not, as the expiration time is uknown.
    }
    //Check if it there is less than "expirationBuffer" time to the expiration:
    uint expirationBuffer = [[ADAuthenticationSettings sharedInstance] expirationBuffer];
    return [_expiresOn compare:[NSDate dateWithTimeIntervalSinceNow:expirationBuffer]] == NSOrderedAscending;
}

- (BOOL)isEmptyUser
{
    //The userInformation object cannot be constructed with empty or blank string,
    //so its presence guarantees that the user is not empty:
    return !_userInformation;
}

/*! Verifies if the user (as defined by userId) is the same between the two items. */
- (BOOL)isSameUser:(ADTokenCacheItem*) other
{
    THROW_ON_NIL_ARGUMENT(other);
    
    if ([self isEmptyUser])
        return [other isEmptyUser];
    return (nil != other.userInformation && [_userInformation.userId isEqualToString:other.userInformation.userId]);
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

//Serializer:
- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:_resource forKey:@"resource"];
    [aCoder encodeObject:_authority forKey:@"authority"];
    [aCoder encodeObject:_clientId forKey:@"clientId"];
	[aCoder encodeObject:_familyId forKey:@"familyId"];
    [aCoder encodeObject:_accessToken forKey:@"accessToken"];
    [aCoder encodeObject:_accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:_refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:_sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:_expiresOn forKey:@"expiresOn"];
    [aCoder encodeObject:_userInformation forKey:@"userInformation"];
	[aCoder encodeObject:_tombstone forKey:@"tombstone"];
}

//Deserializer:
- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
    SAFE_ARC_RETAIN(_resource);
    _authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
    SAFE_ARC_RETAIN(_authority);
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    SAFE_ARC_RETAIN(_clientId);
	_familyId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"familyId"];
	SAFE_ARC_RETAIN(_familyId);

    _accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    SAFE_ARC_RETAIN(_accessToken);
    _accessTokenType = [aDecoder decodeObjectOfClass:[NSString class]
                                                  forKey:@"accessTokenType"];
    SAFE_ARC_RETAIN(_accessTokenType);
    _sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
    SAFE_ARC_RETAIN(_sessionKey);
    _refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    SAFE_ARC_RETAIN(_refreshToken);
    _expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
    SAFE_ARC_RETAIN(_expiresOn);
    _userInformation = [aDecoder decodeObjectOfClass:[ADUserInformation class] forKey:@"userInformation"];
    SAFE_ARC_RETAIN(_userInformation);
	_tombstone = [aDecoder decodeObjectOfClass:[NSMutableDictionary class] forKey:@"tombstone"];
	SAFE_ARC_RETAIN(_tombstone);
    
    [self calculateHash];
    
    return self;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
        return NO;
    
    if (![object isKindOfClass:[ADTokenCacheItem class]])
        return NO;
    
    ADTokenCacheItem* item = (ADTokenCacheItem*)object;
    
    if (_resource && (!item.resource || ![_resource isEqualToString:item.resource]))
    {
        return NO;
    }
    
    if (![_authority isEqualToString:item.authority])
    {
        return NO;
    }
    
    if (![_clientId isEqualToString:item.clientId])
    {
        return NO;
    }
    
    if (![self isSameUser:item])
    {
        return NO;
    }
    
    return YES;
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"(authority=%@ clientId=%@ accessToken=%@ accessTokenType=%@ refreshToken=%@ resource=%@)",
            _authority, _clientId,
            [NSString adIsStringNilOrBlank:_accessToken] ? @"(nil)" : @"(present)", _accessTokenType,
            [NSString adIsStringNilOrBlank:_refreshToken] ? @"(nil)" : @"(present)", _resource];
}

- (NSString *)clientId
{
    return _clientId;
}

- (void)setClientId:(NSString *)clientId
{
    if (_clientId == clientId)
    {
        return;
    }
    SAFE_ARC_RELEASE(_clientId);
    _clientId = clientId;
    SAFE_ARC_RETAIN(_clientId);
    [self calculateHash];
}

- (ADUserInformation *)userInformation
{
    return _userInformation;
}

- (void)setUserInformation:(ADUserInformation *)userInformation
{
    if (_userInformation == userInformation)
    {
        return;
    }
    SAFE_ARC_RELEASE(_userInformation);
    _userInformation = userInformation;
    SAFE_ARC_RETAIN(_userInformation);
    [self calculateHash];
}

- (NSString *)resource
{
    return _resource;
}

- (void)setResource:(NSString *)resource
{
    if (_resource == resource)
    {
        return;
    }
    SAFE_ARC_RELEASE(_resource);
    _resource = resource;
    SAFE_ARC_RETAIN(_resource);
    [self calculateHash];
}

- (NSString *)authority
{
    return _authority;
}

- (void)setAuthority:(NSString *)authority
{
    if (_authority == authority)
    {
        return;
    }
    SAFE_ARC_RELEASE(_authority);
    _authority = authority;
    SAFE_ARC_RETAIN(_authority);
    [self calculateHash];
}

- (NSDictionary *)tombstone
{
    return _tombstone;
}

@end
