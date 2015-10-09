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

#import "ADALiOS.h"
#import "ADTokenCacheStoreItem.h"
#import "ADProfileInfo.h"
#import "ADOAuth2Constants.h"
#import "ADAuthenticationSettings.h"
#import "ADTokenCacheStoreKey.h"

@implementation ADTokenCacheStoreItem

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    // Default identifier type
    _identifierType = RequiredDisplayableId;
    
    return self;
}

- (id)copyWithZone:(NSZone*)zone
{
    ADTokenCacheStoreItem* item = [[self.class allocWithZone:zone] init];
    
    item.authority = [self.authority copyWithZone:zone];
    item.clientId = [self.clientId copyWithZone:zone];
    item.accessToken = [self.accessToken copyWithZone:zone];
    item.accessTokenType = [self.accessTokenType copyWithZone:zone];
    item.refreshToken = [self.refreshToken copyWithZone:zone];
    item.expiresOn = [self.expiresOn copyWithZone:zone];
    item.profileInfo = [self.profileInfo copyWithZone:zone];
    item.sessionKey = [self.sessionKey copyWithZone:zone];
    item.scopes = [self.scopes copyWithZone:zone];
    
    return item;
}

- (ADTokenCacheStoreKey*)extractKeyWithError:(ADAuthenticationError* __autoreleasing *)error
{
    return [ADTokenCacheStoreKey keyWithAuthority:self.authority
                                         clientId:self.clientId
                                           userId:self.profileInfo.username
                                         uniqueId:self.profileInfo.subject
                                           idType:self.identifierType
                                           policy:self.policy
                                           scopes:self.scopes
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

- (BOOL)isEmptyUser
{
    //The profileInfo object cannot be constructed with empty or blank string,
    //so its presence guarantees that the user is not empty:
    return !self.profileInfo;
}

/*! Verifies if the user (as defined by userId) is the same between the two items. */
- (BOOL)isSameUser:(ADTokenCacheStoreItem*)other
{
    if (!other)
    {
        return NO;
    }
    
    if ([self isEmptyUser])
    {
        return [other isEmptyUser];
    }
    
    return [self.profileInfo.username isEqualToString:other.profileInfo.username];
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

//Serializer:
- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.authority forKey:@"authority"];
    [aCoder encodeObject:self.clientId forKey:@"clientId"];
    [aCoder encodeObject:self.accessToken forKey:@"accessToken"];
    [aCoder encodeObject:self.accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:self.refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:self.sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:self.expiresOn forKey:@"expiresOn"];
    [aCoder encodeObject:self.profileInfo forKey:@"profileInfo"];
    [aCoder encodeObject:self.scopes forKey:@"scopes"];
    [aCoder encodeObject:[ADUserIdentifier stringForType:self.identifierType] forKey:@"identifierType"];
}

//Deserializer:
- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if (self)
    {
        self.authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
        self.clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
        self.accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
        self.accessTokenType = [aDecoder decodeObjectOfClass:[NSString class]
                                                      forKey:@"accessTokenType"];
        self.sessionKey = [aDecoder decodeObjectOfClass:[NSData class] forKey:@"sessionKey"];
        self.refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
        self.expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
        self.scopes = [aDecoder decodeObjectOfClass:[NSSet class] forKey:@"scopes"];
        self.profileInfo = [aDecoder decodeObjectOfClass:[ADProfileInfo class] forKey:@"profileInfo"];
        self.identifierType = [ADUserIdentifier typeFromString:[aDecoder decodeObjectOfClass:[NSString class] forKey:@"identifierType"]];
    }
    return self;
}

+ (ADTokenCacheStoreItem*)itemFromData:(NSData *)data
{
    if (!data)
    {
        return nil;
    }
    
    if (![data isKindOfClass:[NSData class]])
    {
        AD_LOG_ERROR(@"Invalid Keychain Data. Unable to decode NSData into cache item.", AD_ERROR_CACHE_PERSISTENCE, nil);
        return nil;
    }
    
    ADTokenCacheStoreItem* item = (ADTokenCacheStoreItem*)[NSKeyedUnarchiver unarchiveObjectWithData:data];
    
    if (!item)
    {
        AD_LOG_ERROR(@"Invalid Keychain Data. Unable to decode NSData into cache item.", AD_ERROR_CACHE_PERSISTENCE, nil);
        return nil;
    }
    
    return item;
}

- (BOOL)isEqual:(id)object
{
    if (!object)
        return NO;
    
    if (![object isKindOfClass:[ADTokenCacheStoreItem class]])
        return NO;
    
    ADTokenCacheStoreItem* item = (ADTokenCacheStoreItem*)object;
    
    if (![_scopes isEqualToSet:item.scopes])
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
    return [NSString stringWithFormat:@"(authority=%@ clientId=%@ accessToken=%@ accessTokenType=%@ refreshToken=%@ scopes=%@)",
            _authority, _clientId,
            [NSString adIsStringNilOrBlank:_accessToken] ? @"(nil)" : @"(present)", _accessTokenType,
            [NSString adIsStringNilOrBlank:_refreshToken] ? @"(nil)" : @"(present)", _scopes];
}

 - (NSString*)userCacheKey
{
    switch (_identifierType)
    {
        case OptionalDisplayableId:
        case RequiredDisplayableId:
            return _profileInfo.username;
            
        case UniqueId:
            return _profileInfo.subject;
    }
    
    AD_LOG_ERROR_F(@"Unkonwn user identifier type in ADTokenCacheStoreItem", AD_ERROR_CACHE_PERSISTENCE, @"erorr: %d", (int)_identifierType);
    return nil;
}

- (NSData*)copyDataForItem
{
    return [NSKeyedArchiver archivedDataWithRootObject:self];
}

- (BOOL)containsScopes:(NSSet *)scopes
{
    return [scopes isSubsetOfSet:_scopes];
}

@end
