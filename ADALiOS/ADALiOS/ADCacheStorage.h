//
//  ADCacheStorage.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol ADCacheStorage <NSObject>

/*!
    Called on initial storage retrieval
 */
- (NSData*)retrieveStorage;

/*!
    Called when checking if the cache needs to be updated, return nil if nothing has changed since the last storage operation.
    Can be the same implementation as -retrieveStorage, however performance will suffer.
 */
- (NSData*)retrieveIfUpdated;

/*!
    Called by ADAL to update the cache storage
 */
- (void)saveToStorage:(NSData*)data;

@end
