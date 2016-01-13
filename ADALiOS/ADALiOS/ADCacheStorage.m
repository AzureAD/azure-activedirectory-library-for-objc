//
//  ADCacheStorage.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/13/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADCacheStorage.h"
#import "ADKeychainCacheStorage.h"
#import "ADKeychainTokenCacheStore.h"
#import "ADTokenCacheStorageWrapper.h"

@implementation ADCacheStorage : NSObject

+ (id<ADTokenCacheEnumerator>)enumeratorForStorageDelegate:(id<ADCacheStorageDelegate>)delegate
{
    if (!delegate)
    {
        return nil;
    }
    
    if ([delegate isKindOfClass:[ADKeychainCacheStorage class]])
    {
        ADKeychainCacheStorage* keychainDelegate = delegate;
        return [[ADKeychainTokenCacheStore alloc] initWithGroup:[keychainDelegate sharedGroup]];
    }
    
    return [[ADTokenCacheStorageWrapper alloc] initWithStorage:delegate];
}

@end