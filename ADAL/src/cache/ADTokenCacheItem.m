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
{
    NSUInteger _hash;
    NSString* _resource;
    NSString* _authority;
    NSString* _clientId;
    ADUserInformation* _userInformation;
}

@synthesize multiResourceRefreshToken;

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
-(BOOL) isMultiResourceRefreshToken
{
    return [NSString adIsStringNilOrBlank:self.resource]
        && [NSString adIsStringNilOrBlank:self.accessToken]
       && ![NSString adIsStringNilOrBlank:self.refreshToken];
}

-(id) copyWithZone:(NSZone*) zone
{
    ADTokenCacheItem* item = [[self.class allocWithZone:zone] init];
    
    item.resource = [self.resource copyWithZone:zone];
    item.authority = [self.authority copyWithZone:zone];
    item.clientId = [self.clientId copyWithZone:zone];
    item.accessToken = [self.accessToken copyWithZone:zone];
    item.accessTokenType = [self.accessTokenType copyWithZone:zone];
    item.refreshToken = [self.refreshToken copyWithZone:zone];
    item.expiresOn = [self.expiresOn copyWithZone:zone];
    item.userInformation = [self.userInformation copyWithZone:zone];
    item.sessionKey = [self.sessionKey copyWithZone:zone];
    
    return item;
}

- (ADTokenCacheKey*)extractKey:(ADAuthenticationError* __autoreleasing *)error
{
    return [ADTokenCacheKey keyWithAuthority:self.authority
                                         resource:self.resource
                                         clientId:self.clientId
                                            error:error];
}

-(BOOL) isExpired
{
    if (nil == self.expiresOn)
    {
        return NO;//Assume opportunistically that it is not, as the expiration time is uknown.
    }
    //Check if it there is less than "expirationBuffer" time to the expiration:
    uint expirationBuffer = [[ADAuthenticationSettings sharedInstance] expirationBuffer];
    return [self.expiresOn compare:[NSDate dateWithTimeIntervalSinceNow:expirationBuffer]] == NSOrderedAscending;
}

-(BOOL) isEmptyUser
{
    //The userInformation object cannot be constructed with empty or blank string,
    //so its presence guarantees that the user is not empty:
    return !self.userInformation;
}

/*! Verifies if the user (as defined by userId) is the same between the two items. */
-(BOOL) isSameUser: (ADTokenCacheItem*) other
{
    THROW_ON_NIL_ARGUMENT(other);
    
    if ([self isEmptyUser])
        return [other isEmptyUser];
    return (nil != other.userInformation && [self.userInformation.userId isEqualToString:other.userInformation.userId]);
}

+(BOOL) supportsSecureCoding
{
    return YES;
}

//Serializer:
-(void) encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.resource forKey:@"resource"];
    [aCoder encodeObject:self.authority forKey:@"authority"];
    [aCoder encodeObject:self.clientId forKey:@"clientId"];
    [aCoder encodeObject:self.accessToken forKey:@"accessToken"];
    [aCoder encodeObject:self.accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:self.refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:self.sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:self.expiresOn forKey:@"expiresOn"];
    [aCoder encodeObject:self.userInformation forKey:@"userInformation"];
}

//Deserializer:
-(id) initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if (self)
    {
        self.resource = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"resource"];
        self.authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
        self.clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
        self.accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
        self.accessTokenType = [aDecoder decodeObjectOfClass:[NSString class]
                                                      forKey:@"accessTokenType"];
        self.sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
        self.refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
        self.expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
        self.userInformation = [aDecoder decodeObjectOfClass:[ADUserInformation class] forKey:@"userInformation"];
    }
    return self;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
        return NO;
    
    if (![object isKindOfClass:[ADTokenCacheItem class]])
        return NO;
    
    ADTokenCacheItem* item = (ADTokenCacheItem*)object;
    
    if (self.resource && (!item.resource || ![self.resource isEqualToString:item.resource]))
    {
        return NO;
    }
    
    if (![self.authority isEqualToString:item.authority])
    {
        return NO;
    }
    
    if (![self.clientId isEqualToString:item.clientId])
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
