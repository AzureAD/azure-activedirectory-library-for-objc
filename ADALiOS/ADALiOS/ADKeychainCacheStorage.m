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
- (BOOL)retrieveStorage:(NSData * __nonnull * __nullable)data
                  error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    (void)data;
    (void)error;
    
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return NO;
}

/*!
    Called when checking if the cache needs to be updated, return nil if nothing has changed since the last storage operation.
    Can be the same implementation as -retrieveStorage, however performance will suffer.
 */
- (BOOL)retrieveIfUpdated:(NSData * __nonnull * __nullable)data
                    error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    (void)data;
    (void)error;
    
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return NO;
}

/*!
    Called by ADAL to update the cache storage
 */
- (BOOL)saveToStorage:(nullable NSData*)data
                error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error
{
    (void)data;
    (void)error;
    
    @throw @"Do not call any ADCacheStorageDelegate methods on ADKeychainCacheStorage.";
    
    return NO;
}


@end
