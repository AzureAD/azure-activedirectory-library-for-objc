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

#import "ADCacheTombstoneWrapper.h"
#import "ADTokenCacheItem.h"

@implementation ADCacheTombstoneWrapper
{
    id<ADTokenCacheAccessor> _cache;
}

-(id) init
{
    //Should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id)initWithCache:(id<ADTokenCacheAccessor>)cache
{
    if (!cache)
    {
        return nil;
    }
    
    _cache = cache;
    
    return self;
}

#pragma mark -
#pragma mark ADTokenCacheAccessor implementation

/*! Return a copy of all items. The array will contain ADTokenCacheItem objects,
 containing all of the cached information. Returns an empty array, if no items are found.
 Returns nil in case of error. */
- (NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __autoreleasing *)error
{
    return [_cache allItems:error];
}

/*!
 @param key      The key of the item.
 @param userId   The specific user whose item is needed. May be nil, in which
 case the item for the first user in the cache will be returned.
 @param error    Will be set only in case of ambiguity. E.g. if userId is nil
 and we have tokens from multiple users. If the cache item is not
 present, the error will not be set.
 Note that tombstones will not be retrieved by this function.
 */
- (ADTokenCacheItem*)getItemWithKey:(ADTokenCacheKey *)key
                             userId:(NSString *)userId
                              error:(ADAuthenticationError * __autoreleasing *)error
{
    ADTokenCacheItem* item = [_cache getItemWithKey:key userId:userId error:error];
    if ([item tombstone])
    {
        return nil;
    }
    else
    {
        return item;
    }
}


/*!
 @param  item    The item to remove/tombstone from the cache, depending on the tombstone property of item.
 @param  error   (Optional) In the case of an error this will be filled with the
 error details.
 
 @return YES if the item was successfully removed/tombstoned. NO otherwise.
 */
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    if ([item tombstone])
    {
        return [_cache addOrUpdateItem:item error:error];
    }
    else
    {
        return [_cache removeItem:item error:error];
    }
}

/*!
 Ensures the cache contains an item matching the passed in item, adding or updating the
 item as necessary.
 
 @param  item    The item to add to the cache, or update if an item matching the key and
 userId already exists in the cache.
 @param  error   (Optional) In the case of an error this will be filled with the
 error details.
 */
- (BOOL)addOrUpdateItem:(ADTokenCacheItem *)item
                  error:(ADAuthenticationError * __autoreleasing*)error
{
    return [_cache addOrUpdateItem:item error:error];
}

@end
