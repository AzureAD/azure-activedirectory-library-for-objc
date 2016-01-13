//
//  ADTokenCacheStorageWrapper.m
//  ADALiOS
//
//  This class provides a ADTokenCacheStoring interface around the provided ADCacheStorage interface.
//
//  It serializes and deserializes the token from the data blob provided and validates cache format.
//  Note, this class is only used on iOS if the developer provided a cache storage inteface, on Mac
//  OS X this is the only way to persist tokens.
//
//  The cache itself is a serialized collection of object and dictionaries in the following schema:
//
//  root
//    |- version - a NSString with a number specify the version of the cache
//    |- cache   - a NSDictionary containing all the tokens
//         |- [ADTokenCacheStoreKey] - A NSDictionary, keyed off of an ADTokenCacheStoreKey
//                      |- <user id> - A NSDictionary, keyed with an NSString of the userID
//                             |- idtoken - An NSString of the idtoken of the user
//                             |- tokens  - An NSArray of ADTokenCacheStoreItems of all the tokens for that user)
//                                              (the ADUserInformation on those items will be nil'd out to reduce space
//                                               necessary, and rehydrated from the idtoken by this wrapper.)
//
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADTokenCacheStorageWrapper.h"
#import "ADAuthenticationError.h"
#import "ADLogger+Internal.h"
#import "ADErrorCodes.h"
#import "ADTokenCacheStoreKey.h"
#import "ADTokenCacheStoreItem.h"
#import "ADUserInformation.h"

#define CURRENT_CACHE_VERSION 1

#define CHECK_ERROR(_cond, _code, _details) { \
    if (!(_cond)) { \
        ADAuthenticationError* _AD_ERROR = [ADAuthenticationError errorFromAuthenticationError:_code protocolCode:nil errorDetails:_details]; \
        if (error) { *error = _AD_ERROR; } \
        return NO; \
    } \
}

@implementation ADTokenCacheStorageWrapper
{
    NSDictionary* _cache;
    id<ADCacheStorage> _storage;
}

- (id)initWithStorage:(id<ADCacheStorage>)storage
{
    if (!storage)
    {
        return nil;
    }
    
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _storage = storage;
    
    [self updateCache:[storage retrieveStorage] error:nil];
    
    return self;
}

- (BOOL)validateCache:(NSDictionary*)dict
                error:(ADAuthenticationError * __autoreleasing *)error
{
    NSString* version = [dict objectForKey:@"version"];
    CHECK_ERROR(version, AD_ERROR_BAD_CACHE_FORMAT, @"Missing version number from cache.");
    CHECK_ERROR([version integerValue] <= CURRENT_CACHE_VERSION, AD_ERROR_CACHE_PERSISTENCE, @"Cache is a future unsupported version.");
    
    NSDictionary* cache = [dict objectForKey:@"tokenCache"];
    CHECK_ERROR(cache, AD_ERROR_BAD_CACHE_FORMAT, @"Missing token cache from data.");
    CHECK_ERROR([cache isKindOfClass:[NSDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"Cache is not a dictionary!");
    
    // Validate that all the objects are the classes we're expecting
    for (id adkey in cache)
    {
        // On the first level we're expecting NSDictionaries keyed off of ADTokenCacheStoreKey
        CHECK_ERROR([adkey isKindOfClass:[ADTokenCacheStoreKey class]], AD_ERROR_BAD_CACHE_FORMAT, @"Key is not the expected class");
        id keyDict = [cache objectForKey:adkey];
        CHECK_ERROR(keyDict, AD_ERROR_BAD_CACHE_FORMAT, @"Expected a dictionary for the token cache key!");
        CHECK_ERROR([keyDict isKindOfClass:[NSDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"Keys should have dictionary objects below them");
        
        for (id userId in keyDict)
        {
            // On the second level we're expecting NSDictionaries keyed off of the user ids (an NSString*) or
            // NSNull if no userId was available.
            CHECK_ERROR([userId isKindOfClass:[NSString class]] || [userId isKindOfClass:[NSNull class]], AD_ERROR_BAD_CACHE_FORMAT, @"User ID key not the expected class type");
            id userDict = [cache objectForKey:userId];
            CHECK_ERROR(userDict, AD_ERROR_BAD_CACHE_FORMAT, @"Expected a dictionary for the user id!");
            CHECK_ERROR([userDict isKindOfClass:[NSDictionary class]], AD_ERROR_BAD_CACHE_FORMAT, @"User IDs should have Dictionaries below them");
            id idtoken = [cache objectForKey:@"idtoken"];
            if (idtoken)
            {
                CHECK_ERROR([idtoken isKindOfClass:[NSString class]], AD_ERROR_BAD_CACHE_FORMAT, @"idtoken was not a string!");
            }
            id tokens = [cache objectForKey:@"tokens"];
            CHECK_ERROR(tokens, AD_ERROR_BAD_CACHE_FORMAT, @"There should be tokens in the user dictionary");
            CHECK_ERROR([tokens isKindOfClass:[NSArray class]], AD_ERROR_BAD_CACHE_FORMAT, @"tokens was not an NSArray!");
            
            for (id token in tokens)
            {
                CHECK_ERROR([token isKindOfClass:[ADTokenCacheStoreItem class]], AD_ERROR_BAD_CACHE_FORMAT, @"token was not a token cache store item!");
            }
        }
    }
    
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

- (BOOL)checkCache:(ADAuthenticationError * __autoreleasing *)error
{
    NSData* update = [_storage retrieveIfUpdated];
    if (update)
    {
        return [self updateCache:update error:error];
    }
    
    return YES;
}

#pragma mark -

- (void)addToItems:(nonnull NSMutableArray *)items
         forUserId:(nonnull NSString *)userId
    fromDictionary:(nonnull NSDictionary *)dict
{
    NSDictionary* userDict = [dict objectForKey:userId];
    if (!userDict)
    {
        return;
    }
    
    ADUserInformation* userInfo = nil;
    
    NSArray* tokens = [userDict objectForKey:@"tokens"];
    if (!tokens)
    {
        return;
    }
    
    // Rehydrate the idtoken
    NSString* idToken = [userDict objectForKey:@"idtoken"];
    if (idToken)
    {
        userInfo = [ADUserInformation userInformationWithIdToken:idToken error:nil];
    }
    
    // Go through all the cache items
    for (ADTokenCacheStoreItem* item in tokens)
    {
        // Re-add the user information
        item.userInformation = userInfo;
        
        [items addObject:item];
    }
}

- (void)addToItems:(nonnull NSMutableArray *)items
            forKey:(nonnull ADTokenCacheStoreKey *)key
            userId:(nullable NSString *)userId
{
    NSDictionary* users = [_cache objectForKey:key];
    if (!users)
    {
        return;
    }
    
    if (userId)
    {
        [self addToItems:items forUserId:userId fromDictionary:users];
    }
    else
    {
        for (NSString* aUserId in users)
        {
            [self addToItems:items forUserId:aUserId fromDictionary:users];
        }
    }
}

- (NSArray<ADTokenCacheStoreItem *> *)getItemsWithKey:(nullable ADTokenCacheStoreKey *)key
                                               userId:(nullable NSString *)userId
                                                error:(ADAuthenticationError *__autoreleasing *)error
{
    @synchronized(self)
    {
        if (![self checkCache:error])
        {
            return nil;
        }
        
        if (!_cache)
        {
            return nil;
        }
        
        NSMutableArray* items = [NSMutableArray new];
        
        if (key)
        {
            // If a key is specified only pull up items for that key
            [self addToItems:items
                      forKey:key
                      userId:userId];
        }
        else
        {
            // Otherwise go through the whole cache and add all items that match the userId
            for (ADTokenCacheStoreKey* adKey in _cache)
            {
                [self addToItems:items
                          forKey:adKey
                          userId:userId];
            }
        }
        
        return items;
    }
}

#pragma mark -
#pragma mark ADTokenCacheStorage Protocol Implementation

/*! Return a copy of all items. The array will contain ADTokenCacheStoreItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheStoreItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:nil userId:nil error:error];
}

/*! May return nil, if no cache item corresponds to the requested key
 @param key: The key of the item.
 @param user: The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error: Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not present,
 the error will not be set. */
- (ADTokenCacheStoreItem *)getItemWithKey:(ADTokenCacheStoreKey *)key
                                   userId:(NSString *)userId
                                    error:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray<ADTokenCacheStoreItem *> * items = [self getItemsWithKey:key userId:userId error:error];
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
 array should contain only ADTokenCacheStoreItem objects. Returns an empty array,
 if no items are found. Returns nil (and sets the error parameter) in case of error.*/
- (NSArray<ADTokenCacheStoreItem *> *)getItemsWithKey:(ADTokenCacheStoreKey*)key
                                                error:(ADAuthenticationError* __autoreleasing*)error
{
    return [self getItemsWithKey:key userId:nil error:error];
}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error: in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (void)addOrUpdateItem:(ADTokenCacheStoreItem *)item
                  error:(ADAuthenticationError * __autoreleasing*)error
{
    
}

/*! Clears token cache details for specific keys.
 @param key: the key of the cache item. Key can be extracted from the ADTokenCacheStoreItem using
 the method 'extractKeyWithError'
 @param userId: The user for which the item will be removed. Can be nil, in which case items for all users with
 the specified key will be removed.
 The method does not raise an error, if the item is not found.
 */
- (void)removeItemWithKey:(ADTokenCacheStoreKey *)key
                   userId:(NSString *)userId
                    error:(ADAuthenticationError * __autoreleasing *)error
{
    
}

@end
