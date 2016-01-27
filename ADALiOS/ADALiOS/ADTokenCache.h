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

#define CURRENT_WRAPPER_CACHE_VERSION 1.0

@class ADAuthenticationError;
@class ADTokenCache;
@class ADTokenCacheItem;

@protocol ADTokenCacheDelegate <NSObject>

- (void)willAccessCache:(nonnull ADTokenCache *)cache;
- (void)didAccessCache:(nonnull ADTokenCache *)cache;
- (void)willWriteCache:(nonnull ADTokenCache *)cache;
- (void)didWriteCache:(nonnull ADTokenCache *)cache;

@end

@interface ADTokenCache : NSObject
{
    NSMutableDictionary* _cache;
    id<ADTokenCacheDelegate> _delegate;
}

- (void)setDelegate:(nullable id<ADTokenCacheDelegate>)delegate;

- (nullable NSData *)serialize;
- (BOOL)deserialize:(nullable NSData*)data
              error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end
