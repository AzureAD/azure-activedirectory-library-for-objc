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
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"

@implementation ADTokenCacheItem

@synthesize accessToken = _accessToken;
@synthesize accessTokenType = _accessTokenType;
@synthesize expiresOn = _expiresOn;
@synthesize refreshToken = _refreshToken;
@synthesize sessionKey = _sessionKey;
@synthesize familyId = _familyId;
@synthesize storageAuthority = _storageAuthority;

+ (void)load
{
    // This class was named "ADTokenCacheStoreItem" in ADAL 1.x, to maintain backwards compatibility
    // we set class name mappings for this class.
    [NSKeyedArchiver setClassName:@"ADTokenCacheStoreItem" forClass:self];
    [NSKeyedUnarchiver setClass:self forClassName:@"ADTokenCacheStoreItem"];
}

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
    return [NSString msidIsStringNilOrBlank:_resource]
        && [NSString msidIsStringNilOrBlank:_accessToken]
       && ![NSString msidIsStringNilOrBlank:_refreshToken];
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
    item->_additionalServer = [_additionalServer copyWithZone:zone];
    
    [item calculateHash];
    
    return item;
}

- (ADTokenCacheKey*)extractKey:(ADAuthenticationError* __autoreleasing *)error
{
    if (_storageAuthority)
    {
        return [ADTokenCacheKey keyWithAuthority:_storageAuthority
                                        resource:_resource
                                        clientId:_clientId
                                           error:error];
    }
    
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
    [aCoder encodeObject:_additionalServer forKey:@"additionalServer"];
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
	_familyId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"familyId"];

    _accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    _accessTokenType = [aDecoder decodeObjectOfClass:[NSString class]
                                                  forKey:@"accessTokenType"];
    _sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
    _refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    _expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
    _userInformation = [aDecoder decodeObjectOfClass:[ADUserInformation class] forKey:@"userInformation"];
    _additionalServer = [aDecoder decodeObjectOfClass:[NSDictionary class] forKey:@"additionalServer"];
    
    [self calculateHash];
    
    return self;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
    {
        return NO;
    }
    
    if (self == object)
    {
        return YES;
    }
    
    if (![object isKindOfClass:[ADTokenCacheItem class]])
    {
        return NO;
    }
    
    ADTokenCacheItem *rhs = (ADTokenCacheItem *)object;
    
    BOOL result = YES;
    
    result &= [self.resource isEqualToString:rhs.resource] || (self.resource == rhs.resource);
    result &= [self.authority isEqualToString:rhs.authority] || (self.authority == rhs.authority);
    result &= [self.clientId isEqualToString:rhs.clientId] || (self.clientId == rhs.clientId);
    result &= [self.familyId isEqualToString:rhs.familyId] || (self.familyId == rhs.familyId);
    result &= [self.accessToken isEqualToString:rhs.accessToken] || (self.accessToken == rhs.accessToken);
    result &= [self.accessTokenType isEqualToString:rhs.accessTokenType] || (self.accessTokenType == rhs.accessTokenType);
    result &= [self.refreshToken isEqualToString:rhs.refreshToken] || (self.refreshToken == rhs.refreshToken);
    result &= [self.expiresOn isEqualToDate:rhs.expiresOn] || (self.expiresOn == rhs.expiresOn);
    result &= [self.userInformation isEqual:rhs.userInformation]  || (self.userInformation == rhs.userInformation);
    result &= [self.sessionKey isEqualToData:rhs.sessionKey] || (self.sessionKey == rhs.sessionKey);
    result &= [self.additionalServer isEqualToDictionary:rhs.additionalServer] || (self.additionalServer == rhs.additionalServer);

    return result;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"(authority=%@ clientId=%@ accessToken=%@ accessTokenType=%@ refreshToken=%@ resource=%@)",
            _authority, _clientId,
            [NSString msidIsStringNilOrBlank:_accessToken] ? @"(nil)" : [_accessToken msidTokenHash], _accessTokenType,
            [NSString msidIsStringNilOrBlank:_refreshToken] ? @"(nil)" : [_refreshToken msidTokenHash], _resource];
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
    _clientId = [clientId copy];
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
    _userInformation = userInformation;
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
    _resource = [resource copy];
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
    _authority = [authority copy];
    [self calculateHash];
}

@end
