//
//  ADCacheStorage.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ADTokenCacheEnumerator.h"

@protocol ADCacheStorageDelegate <NSObject>

/*!
    Called on initial storage retrieval
 
    @param  data    A double pointer to the cached data, return nil if there is none.
    @param  error   Optional error parameter to provide more error details
 
    @return NO if an error occured
 */
- (BOOL)retrieveStorage:(NSData * __nonnull * __nullable)data
                  error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
    Called when checking if the cache needs to be updated,. Can be the same implementation as -retrieveStorage, however performance will suffer.
 
    @param  data    A double pointer to return the cached data, return nil if there have been
                    no changes since the cache has been read or updated.
    @param  error   Optional error parameter to provide more error details
 
    @return NO if an error occured
 */
- (BOOL)retrieveIfUpdated:(NSData * __nonnull * __nullable)data
                    error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

/*!
    Called by ADAL to update the cache storage
 */
- (BOOL)saveToStorage:(nullable NSData*)data
                error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end


@interface ADCacheStorage : NSObject

+ (nullable id<ADTokenCacheEnumerator>)enumeratorForStorageDelegate:(nullable id<ADCacheStorageDelegate>)delegate;

@end