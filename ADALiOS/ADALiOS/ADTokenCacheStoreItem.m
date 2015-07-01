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

#import "ADTokenCacheStoreItem.h"
#import "ADUserInformation.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheStoreKey.h"
#import "NSString+ADHelperMethods.h"

@implementation ADTokenCacheStoreItem

@synthesize accessToken               = _accessToken;
@synthesize accessTokenType           = _accessTokenType;
@synthesize authority                 = _authority;
@synthesize clientId                  = _clientId;
@synthesize expiresOn                 = _expiresOn;
@synthesize multiResourceRefreshToken = _multiResourceRefreshToken;
@synthesize refreshToken              = _refreshToken;
@synthesize resource                  = _resource;
@synthesize userInformation           = _userInformation;
@synthesize sessionKey                = _sessionKey;

- (void)dealloc
{
    AD_LOG_VERBOSE(@"ADTokenCacheStoreItem", @"dealloc");
    
    SAFE_ARC_RELEASE(_accessToken);
    SAFE_ARC_RELEASE(_accessTokenType);
    SAFE_ARC_RELEASE(_authority);
    SAFE_ARC_RELEASE(_clientId);
    SAFE_ARC_RELEASE(_expiresOn);
    SAFE_ARC_RELEASE(_refreshToken);
    SAFE_ARC_RELEASE(_resource);
    SAFE_ARC_RELEASE(_userInformation);
    SAFE_ARC_RELEASE(_sessionKey);
    SAFE_ARC_SUPER_DEALLOC();
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
    ADTokenCacheStoreItem* item = [[self.class allocWithZone:zone] init];
    
    item->_resource = [self.resource copyWithZone:zone];
    item->_authority = [self.authority copyWithZone:zone];
    item->_clientId = [self.clientId copyWithZone:zone];
    item->_accessToken = [self.accessToken copyWithZone:zone];
    item->_accessTokenType = [self.accessTokenType copyWithZone:zone];
    item->_refreshToken = [self.refreshToken copyWithZone:zone];
    item->_expiresOn = [self.expiresOn copyWithZone:zone];
    item->_userInformation = [self.userInformation copyWithZone:zone];
    item->_sessionKey = [self.sessionKey copyWithZone:zone];
    
    return item;
}

-(ADTokenCacheStoreKey*) extractKeyWithError: (ADAuthenticationError* __autoreleasing *) error
{
    return [ADTokenCacheStoreKey keyWithAuthority:self.authority
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
-(BOOL) isSameUser: (ADTokenCacheStoreItem*) other
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
        self.accessTokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessTokenType"];
        self.sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
        self.refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
        self.expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
        self.userInformation = [aDecoder decodeObjectOfClass:[ADUserInformation class] forKey:@"userInformation"];
    }
    return self;
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"(authority=%@ clientId=%@ accessToken=%@ accessTokenType=%@ refreshToken=%@ resource=%@)",
            _authority, _clientId,
            [NSString adIsStringNilOrBlank:_accessToken] ? @"(nil)" : @"(present)", _accessTokenType,
            [NSString adIsStringNilOrBlank:_refreshToken] ? @"(nil)" : @"(present)", _resource];
}

@end
