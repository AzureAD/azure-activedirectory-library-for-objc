//
//  ADKeychainCacheStorage.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/13/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADKeychainCacheStorage.h"

@implementation ADKeychainCacheStorage
{
    NSString* _sharedGroup;
}

- (id)init
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    _sharedGroup = @"com.microsoft.adalcache";
    
    return self;
}

- (id)initWithKeychainGroup:(NSString*)sharedGroup
{
    if (!(self = [super init]))
    {
        return nil;
    }
    
    if (!sharedGroup)
    {
        sharedGroup = [[NSBundle mainBundle] bundleIdentifier];
    }
    
    _sharedGroup = sharedGroup;
    
    return self;
}

- (NSString *)sharedGroup
{
    return _sharedGroup;
}

#pragma mark -
#pragma mark ADCacheStorageDelegate

/*!
    Called on initial storage retrieval
 */
- (NSData*)retrieveStorage
{
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return nil;
}

/*!
    Called when checking if the cache needs to be updated, return nil if nothing has changed since the last storage operation.
    Can be the same implementation as -retrieveStorage, however performance will suffer.
 */
- (NSData*)retrieveIfUpdated
{
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return nil;
}

/*!
    Called by ADAL to update the cache storage
 */
- (void)saveToStorage:(NSData*)data
{
    (void)data;
    
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return;
}


@end
