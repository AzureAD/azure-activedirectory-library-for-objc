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

//
//  This class provides a ADTokenCacheStoring interface around the provided ADCacheStorage interface.
//
//  This class deserializes the token cache from the data blob provided by the developer on a -deserialize
//  call and validates cache format.
//
//  Note, this class is only used on Mac OS X. On iOS the only suppport caching interface is
//  ADKeychainTokenCache.
//
//  The cache itself is a serialized collection of object and dictionaries in the following schema:
//
//  root
//    |- version - a NSString with a number specify the version of the cache
//    |- tokenCache - an NSDictionary
//          |- tokens   - a NSDictionary containing all the tokens
//          |     |- [<user_id> - an NSDictionary, keyed off of an NSString of the userId
//          |            |- <ADTokenCacheStoreKey> - An ADTokenCacheItem, keyed with an ADTokenCacheStoreKey
//          |- idtokens - An NSDictionary containing all of the idtokens, keyed off of the userID
//

#import "ADTokenCache.h"
#import "ADAuthenticationError.h"
#import "ADLogger+Internal.h"
#import "ADErrorCodes.h"
#import "ADTokenCacheStoreKey.h"
#import "ADTokenCacheItem.h"
#import "ADUserInformation.h"
#import "ADTokenCache+Internal.h"

#define CHECK_ERROR(_cond, _code, _details) { \
    if (!(_cond)) { \
        ADAuthenticationError* _AD_ERROR = [ADAuthenticationError errorFromAuthenticationError:_code protocolCode:nil errorDetails:_details]; \
        if (error) { *error = _AD_ERROR; } \
        return NO; \
    } \
}

@implementation ADTokenCache

- (void)setDelegate:(nullable id<ADTokenCacheDelegate>)delegate
{
    _delegate = delegate;
    _cache = nil;
    
    if (!delegate)
    {
        return;
    }
    
    [_delegate willAccessCache:self];
    
    [_delegate didAccessCache:self];
}

- (nullable NSData *)serialize
{
    if (!_cache)
    {
        return nil;
    }
    
    NSDictionary* wrapper = @{ @"version" : @CURRENT_WRAPPER_CACHE_VERSION,
                               @"tokenCache" : _cache };
    
    @try
    {
        return [NSKeyedArchiver archivedDataWithRootObject:wrapper];
    }
    @catch (id exception)
    {
        // This should be exceedingly rare as all of the objects in the cache we placed there.
        AD_LOG_ERROR(@"Failed to serialize the cache!", AD_ERROR_BAD_CACHE_FORMAT, nil, nil);
        return nil;
    }
}

- (id)unarchive:(NSData*)data
          error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    @try
    {
        return [NSKeyedUnarchiver unarchiveObjectWithData:data];
    }
    @catch (id expection)
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT
                                               protocolCode:nil
                                               errorDetails:@"Failed to unarchive data blob from -deserialize!"];
        
        if (error)
        {
            *error = adError;
        }
        
        return nil;
    }
}


- (BOOL)deserialize:(nullable NSData*)data
              error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    // Start by dropping our existing cache
    _cache = nil;
    
    // If they pass in nil on deserialize that means to drop the cache
    if (!data)
    {
        return YES;
    }
    
    id cache = [self unarchive:data error:error];
    if (!cache)
    {
        return NO;
    }
    
    if (![self validateCache:cache error:error])
    {
        return NO;
    }
    
    _cache = [cache objectForKey:@"tokenCache"];
    return YES;
}


- (BOOL)updateCache:(NSData*)data
              error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!data)
    {
        if (_cache)
        {
            AD_LOG_WARN(@"nil data provided to -updateCache, dropping old cache", nil, nil);
        }
        else
        {
            AD_LOG_INFO(@"No data provided for cache.", nil, nil);
        }
        
        _cache = nil;
        return YES;
    }
    
    // Unarchive the data first
    NSDictionary* dict = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    CHECK_ERROR(dict, AD_ERROR_BAD_CACHE_FORMAT, @"Unable to unarchive data provided by cache storage!");

    if (![self validateCache:dict error:error])
    {
        return NO;
    }
    
    _cache = [dict objectForKey:@"tokenCache"];
    
    return YES;
}

#pragma mark -

- (void)addToItems:(nonnull NSMutableArray *)items
    fromDictionary:(nonnull NSDictionary *)dictionary
               key:(nonnull ADTokenCacheStoreKey *)key
          userInfo:(ADUserInformation *)userInfo
{
    ADTokenCacheItem* item = [dictionary objectForKey:key];
    if (item)
    {
        item.userInformation = userInfo;
        item = [item copy];
        
        [items addObject:item];
    }
}

- (void)addToItems:(nonnull NSMutableArray *)items
         forUserId:(nonnull NSString *)userId
            tokens:(nonnull NSDictionary *)tokens
          idtokens:(NSDictionary *)idtokens
               key:(ADTokenCacheStoreKey *)key
{
    NSDictionary* userTokens = [tokens objectForKey:userId];
    if (!userTokens)
    {
        return;
    }
    
    NSString* idtoken = [idtokens objectForKey:userId];
    ADUserInformation* userInfo = nil;
    if (idtoken)
    {
        // If this fails the error will still get logged below, but that doesn't mean we
        // won't necessarily not have valid tokens for the user.
        userInfo = [ADUserInformation userInformationWithIdToken:idtoken error:nil];
    }
    
    // Add items matching the key for this user
    if (key)
    {
        [self addToItems:items fromDictionary:userTokens key:key userInfo:userInfo];
    }
    else
    {
        for (id adkey in userTokens)
        {
            [self addToItems:items fromDictionary:userTokens key:adkey userInfo:userInfo];
        }
    }
}

- (NSArray<ADTokenCacheItem *> *)getItemsWithKey:(nullable ADTokenCacheStoreKey *)key
                                          userId:(nullable NSString *)userId
                                           error:(ADAuthenticationError *__autoreleasing *)error
{
    (void)error;
    
    @synchronized(self)
    {
        [_delegate willAccessCache:self];
        NSArray<ADTokenCacheItem *> * result = [self getItemsImplKey:key userId:userId];
        [_delegate didAccessCache:self];
        
        return result;
    }
}

- (NSArray<ADTokenCacheItem *> *)getItemsImplKey:(nullable ADTokenCacheStoreKey *)key
                                          userId:(nullable NSString *)userId
{
    if (!_cache)
    {
        return nil;
    }
    
    NSMutableArray* items = [NSMutableArray new];
    NSDictionary* tokens = [_cache objectForKey:@"tokens"];
    if (!tokens)
    {
        return nil;
    }
    
    
    NSDictionary* idtokens = [_cache objectForKey:@"idtokens"];
    if (userId)
    {
        // If we have a specified userId then we only look for that one
        [self addToItems:items forUserId:userId tokens:tokens idtokens:idtokens key:key];
    }
    else
    {
        // Otherwise we have to traverse all of the users in the cache
        for (NSString* userId in tokens)
        {
            [self addToItems:items forUserId:userId tokens:tokens idtokens:idtokens key:key];
        }
    }
    
    return items;
}


/*! Clears token cache details for specific keys.
 @param key: the key of the cache item. Key can be extracted from the ADTokenCacheItem using
 the method 'extractKeyWithError'
 @param userId: The user for which the item will be removed. Can be nil, in which case items for all users with
 the specified key will be removed.
 The method does not raise an error, if the item is not found.
 */
- (BOOL)removeItem:(ADTokenCacheItem *)item
             error:(ADAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    BOOL result = [self removeImpl:item error:error];
    [_delegate didWriteCache:self];
    return result;
}

- (BOOL)removeImpl:(ADTokenCacheItem *)item
             error:(ADAuthenticationError * __autoreleasing *)error
{
    ADTokenCacheStoreKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    
    NSString* userId = item.userInformation.userId;
    if (!userId)
    {
        userId = @"";
    }
    
    NSMutableDictionary* tokens = [_cache objectForKey:@"tokens"];
    if (!tokens)
    {
        return YES;
    }
    
    NSMutableDictionary* userTokens = [tokens objectForKey:userId];
    if (!userTokens)
    {
        return YES;
    }
    
    if (![userTokens objectForKey:key])
    {
        return YES;
    }
    
    [userTokens removeObjectForKey:key];
    
    // Check to see if we need to remove the idtoken
    if (!userTokens.count)
    {
        [tokens removeObjectForKey:userId];
        [[_cache objectForKey:@"idtokens"] removeObjectForKey:userId];
    }
    
    return YES;
}

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:nil userId:nil error:error];
}

@end


@implementation ADTokenCache (Internal)

- (BOOL)validateCache:(NSDictionary*)dict
                error:(ADAuthenticationError * __autoreleasing *)error
{
    CHECK_ERROR([dict isKindOfClass:[NSDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"Root level object of cache is not an NSDictionary!");
    
    NSString* version = [dict objectForKey:@"version"];
    CHECK_ERROR(version, AD_ERROR_BAD_CACHE_FORMAT, @"Missing version number from cache.");
    CHECK_ERROR([version floatValue] <= CURRENT_WRAPPER_CACHE_VERSION, AD_ERROR_CACHE_PERSISTENCE, @"Cache is a future unsupported version.");
    
    NSDictionary* cache = [dict objectForKey:@"tokenCache"];
    CHECK_ERROR(cache, AD_ERROR_BAD_CACHE_FORMAT, @"Missing token cache from data.");
    CHECK_ERROR([cache isKindOfClass:[NSMutableDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"Cache is not a dictionary!");
    
    NSDictionary* tokens = [cache objectForKey:@"tokens"];
    
    if (tokens)
    {
        CHECK_ERROR([tokens isKindOfClass:[NSMutableDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"tokens must be a mutable dictionary.");
        for (id userId in tokens)
        {
            // On the second level we're expecting NSDictionaries keyed off of the user ids (an NSString*) or
            // NSNull if no userId was available.
            CHECK_ERROR([userId isKindOfClass:[NSString class]] || [userId isKindOfClass:[NSNull class]], AD_ERROR_BAD_CACHE_FORMAT, @"User ID key not the expected class type");
            id userDict = [tokens objectForKey:userId];
            CHECK_ERROR([userDict isKindOfClass:[NSMutableDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"User ID should have mutable dictionaries in the cache");
            
            for (id adkey in userDict)
            {
                // On the first level we're expecting NSDictionaries keyed off of ADTokenCacheStoreKey
                CHECK_ERROR([adkey isKindOfClass:[ADTokenCacheStoreKey class]], AD_ERROR_BAD_CACHE_FORMAT, @"Key is not the expected class");
                id token = [userDict objectForKey:adkey];
                CHECK_ERROR([token isKindOfClass:[ADTokenCacheItem class]], AD_ERROR_BAD_CACHE_FORMAT, @"Token is not of expected class type!");
            }
        }
    }
    
    
    NSDictionary* idtokens = [cache objectForKey:@"idtokens"];
    if (idtokens)
    {
        CHECK_ERROR([idtokens isKindOfClass:[NSMutableDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"idtokens is not a dictionary!");
        for (id idtoken_key in idtokens)
        {
            CHECK_ERROR([idtoken_key isKindOfClass:[NSString class]], AD_ERROR_BAD_CACHE_FORMAT, @"idtoken key is not a string!");
            id idtoken = [idtokens objectForKey:idtoken_key];
            CHECK_ERROR([idtoken isKindOfClass:[NSString class]], AD_ERROR_BAD_CACHE_FORMAT, @"idtoken is not a string!");
        }
    }
    
    return YES;
}

#pragma mark -
#pragma mark ADTokenCacheAccessor Protocol Implementation

/*! May return nil, if no cache item corresponds to the requested key
 @param key: The key of the item.
 @param user: The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error: Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not present,
 the error will not be set. */
- (ADTokenCacheItem *)getItemWithKey:(ADTokenCacheStoreKey *)key
                                   userId:(NSString *)userId
                                    error:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray<ADTokenCacheItem *> * items = [self getItemsWithKey:key userId:userId error:error];
    if (!items || items.count == 0)
    {
        return nil;
    }
    
    if (items.count == 1)
    {
        return items.firstObject;
    }
    
    ADAuthenticationError* adError =
    [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_MULTIPLE_USERS
                                           protocolCode:nil
                                           errorDetails:@"The token cache store for this resource contain more than one user. Please set the 'userId' parameter to determine which one to be used."];
    if (error)
    {
        *error = adError;
    }
    
    return nil;

}

/*! Returns all of the items for a given key. Multiple items may present,
 if the same resource was accessed by more than one user. The returned
 array should contain only ADTokenCacheItem objects. Returns an empty array,
 if no items are found. Returns nil (and sets the error parameter) in case of error.*/
- (NSArray<ADTokenCacheItem *> *)getItemsWithKey:(ADTokenCacheStoreKey*)key
                                                error:(ADAuthenticationError* __autoreleasing*)error
{
    return [self getItemsWithKey:key userId:nil error:error];
}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error: in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    BOOL result = [self addOrUpdateImpl:item error:error];
    [_delegate didWriteCache:self];
    
    return result;
}

- (BOOL)addOrUpdateImpl:(ADTokenCacheItem *)item
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!item)
    {
        ADAuthenticationError* adError = [ADAuthenticationError errorFromArgument:item argumentName:@"item"];
        if (error)
        {
            *error = adError;
        }
        return NO;
    }
    
    // Copy the item to make sure it doesn't change under us.
    item = [item copy];
    
    ADTokenCacheStoreKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    
    NSMutableDictionary* tokens = nil;
    NSMutableDictionary* idtokens = nil;
    
    if (!_cache)
    {
        // If we don't have a cache that means we need to create one.
        _cache = [NSMutableDictionary new];
        
        tokens = [NSMutableDictionary new];
        idtokens = [NSMutableDictionary new];
        
        [_cache setObject:tokens forKey:@"tokens"];
        [_cache setObject:idtokens forKey:@"idtokens"];
    }
    else
    {
        tokens = [_cache objectForKey:@"tokens"];
        idtokens = [_cache objectForKey:@"idtokens"];
    }
    
    // Grab the userId first
    id userId = item.userInformation.userId;
    if (!userId)
    {
        // If we don't have one (ADFS case) then use an empty string
        userId = @"";
    }
    else
    {
        // Save away the idtoken
        NSString* idtoken = item.userInformation.rawIdToken;
        if (idtoken)
        {
            [idtokens setObject:idtoken forKey:userId];
        }
    }
    
    // Grab the token dictionary for this user id.
    NSMutableDictionary* userDict = [tokens objectForKey:userId];
    if (!userDict)
    {
        userDict = [NSMutableDictionary new];
        [tokens setObject:userDict forKey:userId];
    }
    
    // Nil out the user information
    item.userInformation = nil;
    
    [userDict setObject:item forKey:key];
    
    return YES;
}

@end
