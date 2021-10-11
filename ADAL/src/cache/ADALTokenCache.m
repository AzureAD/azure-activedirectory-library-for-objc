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
//  This class provides a ADALTokenCacheAccessor interface around the provided ADCacheStorage interface.
//
//  This class deserializes the token cache from the data blob provided by the developer on a -deserialize
//  call and validates cache format.
//
//  Note, this class is only used on Mac OS X. On iOS the only suppport caching interface is
//  ADALKeychainTokenCache.
//
//  The cache itself is a serialized collection of object and dictionaries in the following schema:
//
//  root
//    |- version - a NSString with a number specify the version of the cache
//    |- tokenCache - an NSDictionary
//          |- tokens   - a NSDictionary containing all the tokens
//          |     |- [<user_id> - an NSDictionary, keyed off of an NSString of the userId
//          |            |- <ADALTokenCacheStoreKey> - An ADALTokenCacheItem, keyed with an ADALTokenCacheStoreKey

#import "ADALTokenCache.h"
#import "MSIDMacTokenCache.h"
#import "MSIDKeyedArchiverSerializer.h"
#import "ADALAuthenticationErrorConverter.h"
#import "ADALTokenCache+Internal.h"
#import "ADALMSIDDataSourceWrapper.h"
#import "ADALTokenCacheItem.h"
#import "ADALUserInformation.h"
#import "MSIDLegacyTokenCacheKey.h"
#import "ADALHelpers.h"
#import "ADAL_Internal.h"

#include <pthread.h>

@interface ADALTokenCache()

@property (nonatomic, nullable) MSIDMacTokenCache *macTokenCache;
@property (nonatomic, nullable) ADALMSIDDataSourceWrapper *msidDataSourceWrapper;
@property (nonatomic) dispatch_queue_t synchronizationQueue;

@end

@implementation ADALTokenCache

+ (ADALTokenCache *)defaultCache
{
    static dispatch_once_t once;
    static ADALTokenCache * cache = nil;
    
    dispatch_once(&once, ^{
        cache = [ADALTokenCache new];
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
    self.msidDataSourceWrapper = [[ADALMSIDDataSourceWrapper alloc] initWithMSIDDataSource:self.macTokenCache
                                                                              serializer:[MSIDKeyedArchiverSerializer new]];
    
    NSString *queueName = [NSString stringWithFormat:@"com.microsoft.msidmactokencache-%@", [NSUUID UUID].UUIDString];
    self.synchronizationQueue = dispatch_queue_create([queueName cStringUsingEncoding:NSASCIIStringEncoding], DISPATCH_QUEUE_CONCURRENT);
    
    return self;
}

- (void)setDelegate:(nullable id<ADALTokenCacheDelegate>)delegate
{
    dispatch_barrier_sync(self.synchronizationQueue, ^{
        
        if (_delegate == delegate)
        {
            return;
        }
        
        _delegate = delegate;
        [self.macTokenCache clear];
        
    });
    
    dispatch_sync(self.synchronizationQueue, ^{
        
        if (!delegate)
        {
            return;
        }
        
        [_delegate willAccessCache:self];
        [_delegate didAccessCache:self];
        
    });
}

- (nullable NSData *)serialize
{
    return [self.macTokenCache serialize];
}

- (BOOL)deserialize:(nullable NSData*)data
              error:(ADALAuthenticationError **)error
{
    if (!data)
    {
        [self.macTokenCache clear];
        return YES;
    }

    NSError *cacheError = nil;
    
    BOOL result = [self.macTokenCache deserialize:data error:&cacheError];
    
    if (cacheError && error)
    {
        *error = [ADALAuthenticationErrorConverter ADALAuthenticationErrorFromMSIDError:cacheError];
    }
    
    return result;
}

/*! Clears token cache details for specific keys.
    @param item The item to remove from the array.
 */
- (BOOL)removeItem:(ADALTokenCacheItem *)item
             error:(ADALAuthenticationError **)error
{
    return [self.msidDataSourceWrapper removeItem:item error:error];
}

/*! Return a copy of all items. The array will contain ADALTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADALTokenCacheItem *> *)allItems:(ADALAuthenticationError * __autoreleasing *)error
{
    return [self.msidDataSourceWrapper allItems:error];
}

- (BOOL)removeAllForClientId:(NSString *)clientId
                       error:(ADALAuthenticationError **)error
{
    clientId = [clientId msidTrimmedString];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:clientId], clientId, NO);
    
    return [self.msidDataSourceWrapper removeAllForClientId:clientId error:error];
}


- (BOOL)removeAllForUserId:(NSString *)userId
                  clientId:(NSString *)clientId
                     error:(ADALAuthenticationError **)error
{
    userId = [ADALHelpers normalizeUserId:userId];
    clientId = [clientId msidTrimmedString];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:userId], userId, NO);
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:clientId], clientId, NO);
    
    return [self.msidDataSourceWrapper removeAllForUserId:userId
                                                 clientId:clientId
                                                    error:error];
}

- (BOOL)wipeAllItemsForUserId:(NSString *)userId
                        error:(ADALAuthenticationError **)error
{
    userId = [ADALHelpers normalizeUserId:userId];
    RETURN_ON_INVALID_ARGUMENT([NSString msidIsStringNilOrBlank:userId], userId, NO);
    
    return [self.msidDataSourceWrapper wipeAllItemsForUserId:userId error:error];
}

#pragma mark - MSIDMacTokenCacheDelegate

- (void)willAccessCache:(nonnull MSIDMacTokenCache *)cache
{
    dispatch_sync(self.synchronizationQueue, ^{
        [_delegate willAccessCache:self];
    });
}

- (void)didAccessCache:(nonnull MSIDMacTokenCache *)cache
{
    dispatch_sync(self.synchronizationQueue, ^{
        [_delegate didAccessCache:self];
    });
}

- (void)willWriteCache:(nonnull MSIDMacTokenCache *)cache
{
    dispatch_sync(self.synchronizationQueue, ^{
        [_delegate willWriteCache:self];
    });
}

- (void)didWriteCache:(nonnull MSIDMacTokenCache *)cache
{
    dispatch_sync(self.synchronizationQueue, ^{
        [_delegate didWriteCache:self];
    });
}

#pragma mark - Internal

- (id<ADALTokenCacheDelegate>)delegate
{
    return _delegate;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"ADALTokenCache: %@", self.macTokenCache.description];
}

- (BOOL)addOrUpdateItem:(ADALTokenCacheItem *)item
          correlationId:(NSUUID *)correlationId
                  error:(ADALAuthenticationError **)error
{
    return [self.msidDataSourceWrapper addOrUpdateItem:item correlationId:correlationId error:error];
}

#pragma mark - ADALTokenCacheDataSource

/*
 TODO: this code will be removed once integration with MSID core is completed.
 It's just necessary to keep all other code and tests from breaking and to do changes in small PRs
 */

- (ADALTokenCacheItem *)getItemWithKey:(ADALTokenCacheKey *)key
                              userId:(NSString *)userId
                       correlationId:(NSUUID *)correlationId
                               error:(ADALAuthenticationError **)error
{
    return [self.msidDataSourceWrapper getItemWithKey:key userId:userId correlationId:correlationId error:error];
}

- (NSArray <ADALTokenCacheItem *> *)getItemsWithKey:(ADALTokenCacheKey *)key
                                           userId:(NSString *)userId
                                    correlationId:(NSUUID * )correlationId
                                            error:(ADALAuthenticationError **)error
{
    return [self.msidDataSourceWrapper getItemsWithKey:key userId:userId correlationId:correlationId error:error];
}

- (NSDictionary *)getWipeTokenData
{
    return [self.msidDataSourceWrapper getWipeTokenData];
}

@end
