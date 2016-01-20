//
//  ADTokenCacheStorageWrapper.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ADTokenCacheEnumerator.h"
#import "ADCacheStorage.h"

#define CURRENT_WRAPPER_CACHE_VERSION 1.0

@class ADAuthenticationError;

@interface ADTokenCacheStorageWrapper : NSObject <ADTokenCacheEnumerator>
{
    NSMutableDictionary* _cache;
    id<ADCacheStorageDelegate> _storage;
}

- (nullable instancetype)initWithStorage:(nullable id<ADCacheStorageDelegate>)storage;

- (nullable NSArray<ADTokenCacheItem *> *)getItemsWithKey:(nullable ADTokenCacheStoreKey *)key
                                                        userId:(nullable NSString *)userId
                                                         error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (void)updateStorage;
- (BOOL)checkCache:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (BOOL)validateCache:(nullable NSDictionary *)dict
                error:(ADAuthenticationError * __nullable  __autoreleasing * __nullable)error;

@end
