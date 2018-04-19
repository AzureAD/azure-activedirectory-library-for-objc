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

//
//  This class provides a ADTokenCacheAccessor interface around the provided ADCacheStorage interface.
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

#import "ADLegacyMacTokenCache.h"
#import "ADAuthenticationError.h"
#import "ADErrorCodes.h"
#import "ADTokenCacheKey.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheKey.h"
#import "ADAuthenticationSettings.h"

#include <pthread.h>

#define CHECK_ERROR(_cond, _code, _details) { \
    if (!(_cond)) { \
        ADAuthenticationError* _AD_ERROR = [ADAuthenticationError errorFromAuthenticationError:_code protocolCode:nil errorDetails:_details correlationId:nil]; \
        if (error) { *error = _AD_ERROR; } \
        return NO; \
    } \
}

@implementation ADLegacyMacTokenCache

+ (ADLegacyMacTokenCache *)defaultCache
{
    static dispatch_once_t once;
    static ADLegacyMacTokenCache * cache = nil;
    
    dispatch_once(&once, ^{
        cache = [ADLegacyMacTokenCache new];
    });
    
    return cache;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    pthread_rwlock_init(&_lock, NULL);
    
    return self;
}

- (void)dealloc
{
    pthread_rwlock_destroy(&_lock);
}

- (void)setDelegate:(nullable id<ADTokenCacheDelegate>)delegate
{
    if (_delegate == delegate)
    {
        return;
    }
    
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        MSID_LOG_ERROR(nil, @"pthread_rwlock_wrlock failed in setDelegate");
        return;
    }
    
    _delegate = delegate;
    _cache = nil;
    
    pthread_rwlock_unlock(&_lock);
    
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
    
    int err = pthread_rwlock_rdlock(&_lock);
    if (err != 0)
    {
        MSID_LOG_ERROR(nil, @"pthread_rwlock_rdlock failed in serialize");
        return nil;
    }
    NSDictionary* cacheCopy = [_cache mutableCopy];
    pthread_rwlock_unlock(&_lock);
    
    // Using the dictionary @{ key : value } syntax here causes _cache to leak. Yay legacy runtime!
    NSDictionary* wrapper = [NSDictionary dictionaryWithObjectsAndKeys:cacheCopy, @"tokenCache",
                             @CURRENT_WRAPPER_CACHE_VERSION, @"version", nil];
    
    @try
    {
        return [NSKeyedArchiver archivedDataWithRootObject:wrapper];
    }
    @catch (id exception)
    {
        // This should be exceedingly rare as all of the objects in the cache we placed there.
        MSID_LOG_ERROR(nil, @"Failed to serialize the cache!");
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
    @catch (id exception)
    {
        ADAuthenticationError* adError =
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_BAD_FORMAT
                                               protocolCode:nil
                                               errorDetails:@"Failed to unarchive data blob from -deserialize!"
                                              correlationId:nil];
        
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
    pthread_rwlock_wrlock(&_lock);
    BOOL ret = [self deserializeImpl:data error:error];
    pthread_rwlock_unlock(&_lock);
    return ret;
}

- (BOOL)deserializeImpl:(nullable NSData*)data
              error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    // If they pass in nil on deserialize that means to drop the cache
    if (!data)
    {
        _cache = nil;
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
            MSID_LOG_WARN(nil, @"nil data provided to -updateCache, dropping old cache.");
            _cache = nil;
        }
        else
        {
            MSID_LOG_INFO(nil, @"No data provided for cache.");
        }
        return YES;
    }
    
    // Unarchive the data first
    NSDictionary* dict = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    CHECK_ERROR(dict, AD_ERROR_CACHE_BAD_FORMAT, @"Unable to unarchive data provided by cache storage!");

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
               key:(nonnull ADTokenCacheKey *)key
{
    ADTokenCacheItem* item = [dictionary objectForKey:key];
    if (item)
    {
        item = [item copy];
        
        [items addObject:item];
    }
}

- (void)addToItems:(nonnull NSMutableArray *)items
         forUserId:(nonnull NSString *)userId
            tokens:(nonnull NSDictionary *)tokens
               key:(ADTokenCacheKey *)key
{
    NSDictionary* userTokens = [tokens objectForKey:userId];
    if (!userTokens)
    {
        return;
    }
    
    // Add items matching the key for this user
    if (key)
    {
        [self addToItems:items fromDictionary:userTokens key:key];
    }
    else
    {
        for (id adkey in userTokens)
        {
            [self addToItems:items fromDictionary:userTokens key:adkey];
        }
    }
}

- (NSArray<ADTokenCacheItem *> *)getItemsImplKey:(nullable ADTokenCacheKey *)key
                                          userId:(nullable NSString *)userId
{
    if (!_cache)
    {
        return nil;
    }
    
    NSDictionary* tokens = [_cache objectForKey:@"tokens"];
    if (!tokens)
    {
        return nil;
    }
    
    NSMutableArray* items = [NSMutableArray new];
    
    if (userId)
    {
        // If we have a specified userId then we only look for that one
        [self addToItems:items forUserId:userId tokens:tokens key:key];
    }
    else
    {
        // Otherwise we have to traverse all of the users in the cache
        for (NSString* userId in tokens)
        {
            [self addToItems:items forUserId:userId tokens:tokens key:key];
        }
    }
    
    return items;
}


/*! Clears token cache details for specific keys.
    @param item The item to remove from the array.
 */
- (BOOL)removeItem:(ADTokenCacheItem *)item
             error:(ADAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        MSID_LOG_ERROR(nil, @"pthread_rwlock_wrlock failed in removeItem");
        return NO;
    }
    BOOL result = [self removeImpl:item error:error];
    pthread_rwlock_unlock(&_lock);
    [_delegate didWriteCache:self];
    return result;
}

- (BOOL)removeImpl:(ADTokenCacheItem *)item
             error:(ADAuthenticationError * __autoreleasing *)error
{
    ADTokenCacheKey* key = [item extractKey:error];
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
    
    // Check to see if we need to remove the overall dict
    if (!userTokens.count)
    {
        [tokens removeObjectForKey:userId];
    }
    
    return YES;
}

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [self getItemsWithKey:nil userId:nil correlationId:nil error:error];
}

- (id<ADTokenCacheDelegate>)delegate
{
    return _delegate;
}

- (BOOL)validateCache:(NSDictionary*)dict
                error:(ADAuthenticationError * __autoreleasing *)error
{
    CHECK_ERROR([dict isKindOfClass:[NSDictionary class]], AD_ERROR_CACHE_BAD_FORMAT, @"Root level object of cache is not a NSDictionary!");
    
    NSString* version = [dict objectForKey:@"version"];
    CHECK_ERROR(version, AD_ERROR_CACHE_BAD_FORMAT, @"Missing version number from cache.");
    CHECK_ERROR([version floatValue] <= CURRENT_WRAPPER_CACHE_VERSION, AD_ERROR_CACHE_VERSION_MISMATCH, @"Cache is a future unsupported version.");
    
    NSDictionary* cache = [dict objectForKey:@"tokenCache"];
    CHECK_ERROR(cache, AD_ERROR_CACHE_BAD_FORMAT, @"Missing token cache from data.");
    CHECK_ERROR([cache isKindOfClass:[NSMutableDictionary class]], AD_ERROR_CACHE_BAD_FORMAT, @"Cache is not a dictionary!");
    
    NSDictionary* tokens = [cache objectForKey:@"tokens"];
    
    if (tokens)
    {
        CHECK_ERROR([tokens isKindOfClass:[NSMutableDictionary class]], AD_ERROR_CACHE_BAD_FORMAT, @"tokens must be a mutable dictionary.");
        for (id userId in tokens)
        {
            // On the second level we're expecting NSDictionaries keyed off of the user ids (an NSString*)
            CHECK_ERROR([userId isKindOfClass:[NSString class]], AD_ERROR_CACHE_BAD_FORMAT, @"User ID key is not of the expected class type");
            id userDict = [tokens objectForKey:userId];
            CHECK_ERROR([userDict isKindOfClass:[NSMutableDictionary class]], AD_ERROR_CACHE_BAD_FORMAT, @"User ID should have mutable dictionaries in the cache");
            
            for (id adkey in userDict)
            {
                // On the first level we're expecting NSDictionaries keyed off of ADTokenCacheStoreKey
                CHECK_ERROR([adkey isKindOfClass:[ADTokenCacheKey class]], AD_ERROR_CACHE_BAD_FORMAT, @"Key is not of the expected class type");
                id token = [userDict objectForKey:adkey];
                CHECK_ERROR([token isKindOfClass:[ADTokenCacheItem class]], AD_ERROR_CACHE_BAD_FORMAT, @"Token is not of the expected class type!");
            }
        }
    }
    
    return YES;
}

#pragma mark -
#pragma mark ADTokenCacheAccessor Protocol Implementation

/*! May return nil, if no cache item corresponds to the requested key
 @param key The key of the item.
 @param userId The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not present,
 the error will not be set. */
- (ADTokenCacheItem *)getItemWithKey:(ADTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(ADAuthenticationError * __autoreleasing *)error
{
    NSArray<ADTokenCacheItem *> * items = [self getItemsWithKey:key userId:userId correlationId:correlationId error:error];
    
    if (items.count == 0)
    {
        return nil;
    }
    
    for (ADTokenCacheItem* item in items)
    {
        [item logMessage:@"Found"
                   level:MSIDLogLevelWarning
           correlationId:correlationId];
    }
    
    if (items.count == 1)
    {
        return items.firstObject;
    }

    
    ADAuthenticationError* adError =
    [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_MULTIPLE_USERS
                                           protocolCode:nil
                                           errorDetails:@"The token cache store for this resource contains more than one user. Please set the 'userId' parameter to the one that will be used."
                                          correlationId:correlationId];
    if (error)
    {
        *error = adError;
    }
    
    return nil;

}

/*! Extracts the key from the item and uses it to set the cache details. If another item with the
 same key exists, it will be overriden by the new one. 'getItemWithKey' method can be used to determine
 if an item already exists for the same key.
 @param error in case of an error, if this parameter is not nil, it will be filled with
 the error details. */
- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    [_delegate willWriteCache:self];
    int err = pthread_rwlock_wrlock(&_lock);
    if (err != 0)
    {
        MSID_LOG_ERROR_CORR(correlationId, @"pthread_rwlock_wrlock failed in addOrUpdateItem");
        return NO;
    }
    BOOL result = [self addOrUpdateImpl:item correlationId:correlationId error:error];
    pthread_rwlock_unlock(&_lock);
    [_delegate didWriteCache:self];
    
    return result;
}

- (BOOL)addOrUpdateImpl:(ADTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADAuthenticationError * __autoreleasing *)error
{
    if (!item)
    {
        ADAuthenticationError* adError = [ADAuthenticationError errorFromArgument:item argumentName:@"item" correlationId:correlationId];
        if (error)
        {
            *error = adError;
        }
        return NO;
    }
    
    // Copy the item to make sure it doesn't change under us.
    item = [item copy];
    
    ADTokenCacheKey* key = [item extractKey:error];
    if (!key)
    {
        return NO;
    }
    
    NSMutableDictionary* tokens = nil;
    
    if (!_cache)
    {
        // If we don't have a cache that means we need to create one.
        _cache = [NSMutableDictionary new];
        tokens = [NSMutableDictionary new];
        [_cache setObject:tokens forKey:@"tokens"];
    }
    else
    {
        tokens = [_cache objectForKey:@"tokens"];
    }
    
    // Grab the userId first
    id userId = item.userInformation.userId;
    if (!userId)
    {
        // If we don't have one (ADFS case) then use an empty string
        userId = @"";
    }
    
    // Grab the token dictionary for this user id.
    NSMutableDictionary* userDict = [tokens objectForKey:userId];
    if (!userDict)
    {
        userDict = [NSMutableDictionary new];
        [tokens setObject:userDict forKey:userId];
    }
    
    [userDict setObject:item forKey:key];
    return YES;
}

- (NSArray<ADTokenCacheItem *> *)getItemsWithKey:(nullable ADTokenCacheKey *)key
                                          userId:(nullable NSString *)userId
                                   correlationId:(nullable NSUUID *)correlationId
                                           error:(ADAuthenticationError *__autoreleasing *)error
{
    (void)error;
    (void)correlationId;
    
    [_delegate willAccessCache:self];
    int err = pthread_rwlock_rdlock(&_lock);
    if (err != 0)
    {
        MSID_LOG_ERROR_CORR(correlationId, @"pthread_rwlock_rdlock failed in getItemsWithKey");
        return nil;
    }
    NSArray<ADTokenCacheItem *> * result = [self getItemsImplKey:key userId:userId];
    pthread_rwlock_unlock(&_lock);
    
    [_delegate didAccessCache:self];
    
    return result;
}

- (nullable NSDictionary *)getWipeTokenData
{
    // Wiping token data is not yet supported on macOS
    return nil;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"ADTokenCache: %@", _cache];
}

@end
