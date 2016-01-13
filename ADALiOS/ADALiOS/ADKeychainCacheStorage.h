//
//  ADKeychainCacheStorage.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/13/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ADCacheStorage.h"

/*!
    ADKeychainCacheStorage is a special sentinel class for the ADAL v1 Keychain
    Cache. The ADCacheStorageDelegate methods are not actually implemented and
    will throw exceptions if they are called. Use them utility method
    +[ADCacheStorage traversalForStorageDelegate:] to traverse the contents
    of the keychain.
 */

@interface ADKeychainCacheStorage : NSObject <ADCacheStorageDelegate>

/*!
    Create an ADKeychainCacheStorage object with the default keychain sharing
    group ("com.microsoft.adalcache")
 */
- (id)init;

/*!
    Create an ADKeychainCacheStorage object with the specified keychain sharing
    group, note if 'nil' is specified then the application's bundle ID will be
    used instead.
 */
- (id)initWithKeychainGroup:(NSString*)sharedGroup;

- (NSString *)sharedGroup;

@end
