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
    item->_accessToken = [_accessToken copyWithZone:zone];
    item->_accessTokenType = [_accessTokenType copyWithZone:zone];
    item->_refreshToken = [_refreshToken copyWithZone:zone];
    item->_expiresOn = [_expiresOn copyWithZone:zone];
    item->_userInformation = [_userInformation copyWithZone:zone];
    item->_sessionKey = [_sessionKey copyWithZone:zone];
    
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
    [aCoder encodeObject:_accessToken forKey:@"accessToken"];
    [aCoder encodeObject:_accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:_refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:_sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:_expiresOn forKey:@"expiresOn"];
    [aCoder encodeObject:_userInformation forKey:@"userInformation"];
}

//Deserializer:
- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
    _authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    _accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    _accessTokenType = [aDecoder decodeObjectOfClass:[NSString class]
                                                  forKey:@"accessTokenType"];
    _sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
    _refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    _expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
    _userInformation = [aDecoder decodeObjectOfClass:[ADUserInformation class] forKey:@"userInformation"];
    
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
    _clientId = clientId;
    [self calculateHash];
}

- (ADUserInformation *)userInformation
{
    return _userInformation;
}

- (void)setUserInformation:(ADUserInformation *)userInformation
{
    _userInformation = userInformation;
    [self calculateHash];
}

- (NSString *)resource
{
    return _resource;
}

- (void)setResource:(NSString *)resource
{
    _resource = resource;
    [self calculateHash];
}

- (NSString *)authority
{
    return _authority;
}

- (void)setAuthority:(NSString *)authority
{
    _authority = authority;
    [self calculateHash];
}

@end
