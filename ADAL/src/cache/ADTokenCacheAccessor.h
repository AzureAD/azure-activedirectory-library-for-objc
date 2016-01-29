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

#import <Foundation/Foundation.h>

@class ADTokenCacheKey;
@class ADTokenCacheItem;
@class ADAuthenticationError;

@protocol ADTokenCacheAccessor <NSObject>

/*!
    @param key      The key of the item.
    @param userId   The specific user whose item is needed. May be nil, in which
                    case the item for the first user in the cache will be returned.
    @param error    Will be set only in case of ambiguity. E.g. if userId is nil
                    and we have tokens from multiple users. If the cache item is not
                    present, the error will not be set.
 */
- (nullable ADTokenCacheItem *)getItemWithKey:(nonnull ADTokenCacheKey *)key
                                       userId:(nullable NSString *)userId
                                        error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
    Ensures the cache contains an item matching the passed in item, adding or updating the
    item as necessary.
    
    @param  item    The item to add to the cache, or update if an item matching the key and
                    userId already exists in the cache.
    @param  error   (Optional) In the case of an error this will be filled with the
                    error details.
 */
- (BOOL)addOrUpdateItem:(nonnull ADTokenCacheItem *)item
                  error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
    @param  item    The item to remove from the cache
    @param  error   (Optional) In the case of an error this will be filled with the
                    error details.
 
    @return YES if the item was successfully removed, or was not in the cache. If NO
            look
 */
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSArray*)allItems:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end
