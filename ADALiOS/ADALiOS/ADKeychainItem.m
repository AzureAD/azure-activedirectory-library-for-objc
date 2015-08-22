//
//  ADKeychainItem.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 8/18/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import "ADKeychainItem.h"
#import "ADTokenCacheStoreItem+Internal.h"
#import "ADProfileInfo.h"

@implementation ADKeychainToken

- (id)initWithCoder:(NSCoder*)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _scopes = [aDecoder decodeObjectOfClass:[NSSet class] forKey:@"scopes"];
    _accessToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessToken"];
    _accessTokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"accessTokenType"];
    _expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder*)aCoder
{
    [aCoder encodeObject:_scopes forKey:@"scopes"];
    [aCoder encodeObject:_accessToken forKey:@"accessToken"];
    [aCoder encodeObject:_accessTokenType forKey:@"accessTokenType"];
    [aCoder encodeObject:_expiresOn forKey:@"expiresOn"];
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (void)addToTokenItem:(ADTokenCacheStoreItem*)item
{
    // Access token specific properties
    item.scopes = _scopes;
    item.accessToken = _accessToken;
    item.accessTokenType = _accessTokenType;
    item.expiresOn = _expiresOn;
}

@end

@implementation ADKeychainItem
{
    NSMutableArray* _accessTokens;
}

- (id)initWithCoder:(NSCoder*)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _authority = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"authority"];
    _clientId = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"clientId"];
    _sessionKey = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"sessionKey"];
    _refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    _profileInfo = [aDecoder decodeObjectOfClass:[ADProfileInfo class] forKey:@"profileInfo"];
    
    _accessTokens = [aDecoder decodeObjectOfClass:[NSArray class] forKey:@"accessTokens"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder*)aCoder
{
    [aCoder encodeObject:_authority forKey:@"authority"];
    [aCoder encodeObject:_clientId forKey:@"clientId"];
    [aCoder encodeObject:_sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:_refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:_profileInfo forKey:@"profileInfo"];
    [aCoder encodeObject:_accessTokens forKey:@"accessTokens"];
}

- (ADKeychainToken*)tokenForScopes:(NSSet*)scopes
{
    for (ADKeychainToken* token in _accessTokens)
    {
        // Ignore anything in the keychain item that's not the correct class.
        if (![token isKindOfClass:[ADKeychainToken class]])
        {
            continue;
        }
        
        if ([scopes isSubsetOfSet:token.scopes])
        {
            return token;
        }
    }
    
    return nil;
}

- (ADTokenCacheStoreItem*)tokenItem
{
    ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
    
    // User-wide properties
    item.authority = _authority;
    item.clientId = _clientId;
    item.sessionKey = _sessionKey;
    item.profileInfo = _profileInfo;
    item.refreshToken = _refreshToken;
    
    return item;
}

- (NSArray*)allItems
{
    if (!_accessTokens.count)
    {
        return nil;
    }
    
    NSMutableArray* items = [[NSMutableArray alloc] initWithCapacity:_accessTokens.count];
    
    for (ADKeychainToken* token in _accessTokens)
    {
        ADTokenCacheStoreItem* item = [self tokenItem];
        [token addToTokenItem:item];
        
        [items addObject:item];
    }
    
    return items;
}

- (ADTokenCacheStoreItem*)tokenItemForScopes:(NSSet*)scopes
{
    ADKeychainToken* token = [self tokenForScopes:scopes];
    if (!token)
    {
        return nil;
    }
    
    ADTokenCacheStoreItem* item = [self tokenItem];
    [token addToTokenItem:item];
    
    return item;
}

- (void)removeIntersectingTokens:(NSSet*)scopes
{
    NSMutableIndexSet* toRemove = [NSMutableIndexSet indexSet];
    
    NSUInteger cTokens = [_accessTokens count];
    
    for (NSUInteger i = 0; i < cTokens; i++)
    {
        ADKeychainToken* token = _accessTokens[i];
        
        // Ignore anything in the keychain item that's not the correct class.
        if (![token isKindOfClass:[ADKeychainToken class]])
        {
            continue;
        }
        
        if ([scopes isSubsetOfSet:token.scopes])
        {
            [toRemove addIndex:i];
        }
    }
    
    [_accessTokens removeObjectsAtIndexes:toRemove];
}

- (void)updateForTokenItem:(ADTokenCacheStoreItem*)item
{
    _refreshToken = item.refreshToken;
    _authority = item.authority;
    _clientId = item.clientId;
    _sessionKey = item.sessionKey;
    _profileInfo = item.profileInfo;
    
    NSSet* scopes = item.scopes;
    [self removeIntersectingTokens:scopes];
    
    ADKeychainToken* token = [ADKeychainToken new];
    token.accessToken = item.accessToken;
    token.accessTokenType = item.accessTokenType;
    token.expiresOn = item.expiresOn;
    token.scopes = scopes;
    
    [_accessTokens addObject:token];
}

@end
