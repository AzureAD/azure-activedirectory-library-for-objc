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

#import "ADTokenCache.h"
#import "MSIDMacTokenCache.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "MSIDKeyedArchiverSerializer.h"
#import "ADAuthenticationErrorConverter.h"
#import "ADTokenCacheItem+MSIDTokens.h"
#import "MSIDBaseToken.h"
#import "ADUserInformation.h"
#import "ADTokenCache+Internal.h"
#import "MSIDJsonSerializer.h"
#import "ADTokenCacheKey.h"

#include <pthread.h>

@interface ADTokenCache()

@property (nonatomic, nullable) MSIDMacTokenCache *macTokenCache;
@property (nonatomic, nullable) id<MSIDTokenItemSerializer> tokenItemSerializer;

@end

@implementation ADTokenCache

+ (ADTokenCache *)defaultCache
{
    static dispatch_once_t once;
    static ADTokenCache * cache = nil;
    
    dispatch_once(&once, ^{
        cache = [ADTokenCache new];
    });
    
    return cache;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    self.macTokenCache = [MSIDMacTokenCache new];
    self.macTokenCache.delegate = self;
    self.tokenItemSerializer = [MSIDJsonSerializer new];
    
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
    [self.macTokenCache clear];
    
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
    return [self.macTokenCache serialize];
}

- (BOOL)deserialize:(nullable NSData*)data
              error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    return [self.macTokenCache deserialize:data error:error];
}

/*! Clears token cache details for specific keys.
    @param item The item to remove from the array.
 */
- (BOOL)removeItem:(ADTokenCacheItem *)item
             error:(ADAuthenticationError * __autoreleasing *)error
{
    return [self.macTokenCache removeItemsWithKey:[item tokenCacheKey] context:nil error:error];
}

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    MSIDTokenCacheKey *key = [MSIDTokenCacheKey keyForAllItems];
    
    NSError *cacheError = nil;
    
    NSArray<MSIDTokenCacheItem *> *allItems = [self.macTokenCache tokensWithKey:key
                                                                     serializer:[MSIDKeyedArchiverSerializer new]
                                                                        context:nil
                                                                          error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    if (!allItems)
    {
        return nil;
    }
    
    NSMutableArray<ADTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDTokenCacheItem *cacheItem in allItems)
    {
        ADTokenCacheItem *item = [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

#pragma mark - MSIDMacTokenCacheDelegate

- (void)willAccessCache:(nonnull MSIDMacTokenCache *)cache
{
    [_delegate willAccessCache:self];
}

- (void)didAccessCache:(nonnull MSIDMacTokenCache *)cache
{
    [_delegate didAccessCache:self];
}

- (void)willWriteCache:(nonnull MSIDMacTokenCache *)cache
{
    [_delegate willWriteCache:self];
}

- (void)didWriteCache:(nonnull MSIDMacTokenCache *)cache
{
    [_delegate didWriteCache:self];
}

#pragma mark - Internal

- (id<ADTokenCacheDelegate>)delegate
{
    return _delegate;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"ADTokenCache: %@", self.macTokenCache.description];
}

- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADAuthenticationError **)error
{
    MSIDTokenCacheKey *key = [item tokenCacheKey];
    MSIDTokenCacheItem *tokenCacheItem = [item tokenCacheItem];
    
    NSError *cacheError = nil;
    
    BOOL result = [self.macTokenCache saveToken:tokenCacheItem
                                            key:key
                                     serializer:self.tokenItemSerializer
                                        context:nil
                                          error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return NO;
    }
    
    return result;
}

#pragma mark - ADTokenCacheDataSource

/*
 TODO: this code will be removed once integration with MSID core is completed.
 It's just necessary to keep all other code and tests from breaking and to do changes in small PRs
 */

- (ADTokenCacheItem *)getItemWithKey:(ADTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(ADAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *msidKey = [MSIDLegacyTokenCacheKey keyWithAuthority:[NSURL URLWithString:key.authority]
                                                                        clientId:key.clientId
                                                                        resource:key.resource
                                                                    legacyUserId:userId];
    
    NSError *cacheError = nil;
    
    MSIDTokenCacheItem *cacheItem = [self.macTokenCache tokenWithKey:msidKey
                                                          serializer:self.tokenItemSerializer
                                                             context:nil
                                                               error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    return [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
}

- (NSArray <ADTokenCacheItem *> *)getItemsWithKey:(ADTokenCacheKey *)key
                                           userId:(NSString *)userId
                                    correlationId:(NSUUID * )correlationId
                                            error:(ADAuthenticationError **)error
{
    MSIDLegacyTokenCacheKey *msidKey = [MSIDLegacyTokenCacheKey keyWithAuthority:[NSURL URLWithString:key.authority]
                                                                        clientId:key.clientId
                                                                        resource:key.resource
                                                                    legacyUserId:userId];
    
    NSError *cacheError = nil;
    
    NSArray *cacheItems = [self.macTokenCache tokensWithKey:msidKey
                                                 serializer:self.tokenItemSerializer
                                                    context:nil
                                                      error:&cacheError];
    
    if (cacheError)
    {
        if (error) *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:cacheError];
        return nil;
    }
    
    NSMutableArray<ADTokenCacheItem *> *results = [NSMutableArray array];
    
    for (MSIDTokenCacheItem *cacheItem in cacheItems)
    {
        ADTokenCacheItem *item = [[ADTokenCacheItem alloc] initWithMSIDTokenCacheItem:cacheItem];
        
        if (item)
        {
            [results addObject:item];
        }
    }
    
    return results;
}

- (NSDictionary *)getWipeTokenData
{
    return nil;
}

@end
