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

#import "ADKeychainItem.h"
#import "ADTokenCacheStoreItem+Internal.h"
#import "ADProfileInfo.h"

@interface ADKeychainToken : NSObject <NSCoding, NSSecureCoding>

@property NSSet* scopes;

@property NSString* token;
@property NSString* tokenType;
@property NSDate* expiresOn;

- (void)addToTokenItem:(ADTokenCacheStoreItem*)item;

@end

@interface ADKeychainPolicyItem : NSObject <NSCoding, NSSecureCoding>

@property NSString* refreshToken;

- (void)addTokenWithScopes:(NSSet*)scopes
                          toItem:(ADTokenCacheStoreItem*)item;

@end

@implementation ADKeychainToken

- (id)initWithCoder:(NSCoder*)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _scopes = [aDecoder decodeObjectOfClass:[NSSet class] forKey:@"scopes"];
    _token = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"token"];
    _tokenType = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"tokenType"];
    _expiresOn = [aDecoder decodeObjectOfClass:[NSDate class] forKey:@"expiresOn"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder*)aCoder
{
    [aCoder encodeObject:_scopes forKey:@"scopes"];
    [aCoder encodeObject:_token forKey:@"token"];
    [aCoder encodeObject:_tokenType forKey:@"tokenType"];
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
    item.token = _token;
    item.tokenType = _tokenType;
    item.expiresOn = _expiresOn;
}

- (void)updateToTokenItem:(ADTokenCacheStoreItem*)item
{
    _scopes = item.scopes;
    _token = item.token;
    _tokenType = item.tokenType;
    _expiresOn = item.expiresOn;
}

@end

@implementation ADKeychainPolicyItem
{
    @public
    NSMutableArray* _tokens;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    _tokens = [NSMutableArray new];
    
    return self;
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    NSArray* tokens = [aDecoder decodeObjectOfClass:[NSArray class] forKey:@"tokens"];
    if (tokens)
    {
        // Verify everything in here matches the expected class
        for (id token in tokens)
        {
            if (![token isKindOfClass:[ADKeychainToken class]])
            {
                return nil;
            }
        }
        
        _tokens = [NSMutableArray arrayWithArray:tokens];
    }
    else
    {
        _tokens = [NSMutableArray new];
    }
    
    _refreshToken = [aDecoder decodeObjectOfClass:[NSString class] forKey:@"refreshToken"];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:_refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:_tokens forKey:@"tokens"];
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (ADKeychainToken*)tokenWithScopes:(NSSet*)scopes
{
    for (ADKeychainToken* token in _tokens)
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

- (void)addTokenWithScopes:(NSSet*)scopes
                          toItem:(ADTokenCacheStoreItem*)item
{
    item.refreshToken = _refreshToken;
    
    ADKeychainToken* token = [self tokenWithScopes:scopes];
    [token addToTokenItem:item];
}

- (void)removeIntersectingTokens:(NSSet*)scopes
{
    NSMutableIndexSet* toRemove = [NSMutableIndexSet indexSet];
    
    NSUInteger cTokens = [_tokens count];
    
    for (NSUInteger i = 0; i < cTokens; i++)
    {
        ADKeychainToken* token = _tokens[i];
        
        // Ignore anything in the keychain item that's not the correct class.
        if (![token isKindOfClass:[ADKeychainToken class]])
        {
            continue;
        }
        
        if ([scopes intersectsSet:token.scopes])
        {
            [toRemove addIndex:i];
        }
    }
    
    [_tokens removeObjectsAtIndexes:toRemove];
}

- (void)updateToTokenItem:(ADTokenCacheStoreItem*)item
{
    _refreshToken = item.refreshToken;
    
    NSSet* scopes = item.scopes;
    [self removeIntersectingTokens:scopes];
    
    ADKeychainToken* token = [ADKeychainToken new];
    [token updateToTokenItem:item];
    [_tokens addObject:token];
}

@end

@interface ADKeychainItem ()

@property NSString* authority;
@property NSString* clientId;
@property NSData* sessionKey;
@property ADProfileInfo* profileInfo;

@end


@implementation ADKeychainItem
{
    NSMutableDictionary* _policies;
}



+ (ADKeychainItem*)itemForData:(NSData *)data
{
    if (!data)
    {
        return nil;
    }
    
    id item = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    if (![item isKindOfClass:[ADKeychainItem class]])
    {
        return nil;
    }
    
    return item;
}

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _policies = [NSMutableDictionary new];
    
    return self;
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
    _profileInfo = [aDecoder decodeObjectOfClass:[ADProfileInfo class] forKey:@"profileInfo"];
    
    _policies = [[aDecoder decodeObjectOfClass:[NSDictionary class] forKey:@"policies"] mutableCopy];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder*)aCoder
{
    [aCoder encodeObject:_authority forKey:@"authority"];
    [aCoder encodeObject:_clientId forKey:@"clientId"];
    [aCoder encodeObject:_sessionKey forKey:@"sessionKey"];
    [aCoder encodeObject:_profileInfo forKey:@"profileInfo"];
    [aCoder encodeObject:_policies forKey:@"policies"];
}

- (NSData*)data
{
    return [NSKeyedArchiver archivedDataWithRootObject:self];
}

- (ADTokenCacheStoreItem*)tokenItem
{
    ADTokenCacheStoreItem* item = [ADTokenCacheStoreItem new];
    
    // User-wide properties
    item.authority = _authority;
    item.clientId = _clientId;
    item.sessionKey = _sessionKey;
    item.profileInfo = _profileInfo;
    
    return item;
}

- (NSArray*)allItems
{
    if (!_policies.count)
    {
        return nil;
    }
    
    NSMutableArray* items = [NSMutableArray new];
    
    for (id policyKey in _policies)
    {
        ADKeychainPolicyItem* policy = [_policies objectForKey:policyKey];
        for (ADKeychainToken* token in policy->_tokens)
        {
            ADTokenCacheStoreItem* item = [self tokenItem];
            [token addToTokenItem:item];
            
            [items addObject:item];
        }
    }
    
    
    return items;
}

- (ADKeychainPolicyItem*)itemForPolicy:(NSString*)policy
                                create:(BOOL)create
{
    id policyKey = policy ? policy : [NSNull null];
    ADKeychainPolicyItem* item = [_policies objectForKey:policyKey];
    if (!item && create)
    {
        item = [ADKeychainPolicyItem new];
        [_policies setObject:item forKey:policyKey];
    }
    return item;
}

- (ADTokenCacheStoreItem*)tokenItemForPolicy:(NSString*)policy
                                      scopes:(NSSet*)scopes
{
    ADTokenCacheStoreItem* item = [self tokenItem];
    item.policy = policy;
    
    // If no token was found then this is a no-op. We still want to return an item as the
    // refresh token might still be usable.
    ADKeychainPolicyItem* policyItem = [self itemForPolicy:policy create:NO];
    [policyItem addTokenWithScopes:scopes toItem:item];
    
    return item;
}


- (void)updateToTokenItem:(ADTokenCacheStoreItem*)item
{
    _authority = item.authority;
    _clientId = item.clientId;
    _sessionKey = item.sessionKey;
    _profileInfo = item.profileInfo;
    
    ADKeychainPolicyItem* policyItem = [self itemForPolicy:item.policy create:YES];
    [policyItem updateToTokenItem:item];
}

@end
