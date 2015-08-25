//
//  ADKeychainItem.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 8/18/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@class ADProfileInfo;
@class ADTokenCacheStoreItem;

@interface ADKeychainItem : NSObject <NSCoding, NSSecureCoding>

+ (ADKeychainItem*)itemForData:(NSData*)data;

- (ADTokenCacheStoreItem*)tokenItemForPolicy:(NSString*)policy
                                      scopes:(NSSet*)scopes;
- (void)updateToTokenItem:(ADTokenCacheStoreItem*)item;
- (NSData*)data;

/*! @return An array of ADTokenCacheStoreItem(s) for all the access tokens store in this keychain item */
- (NSArray*)allItems;

@end
