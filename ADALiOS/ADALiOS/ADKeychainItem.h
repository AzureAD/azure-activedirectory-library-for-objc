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

@interface ADKeychainToken : NSObject <NSCoding, NSSecureCoding>

@property NSSet* scopes;

@property NSString* accessToken;
@property NSString* accessTokenType;
@property NSDate* expiresOn;

@end

@interface ADKeychainItem : NSObject <NSCoding, NSSecureCoding>

@property NSString* authority;
@property NSString* clientId;
@property NSData* sessionKey;
@property NSString* refreshToken;
@property ADProfileInfo* profileInfo;

- (ADTokenCacheStoreItem*)tokenItemForScopes:(NSSet*)scopes;
- (void)updateForTokenItem:(ADTokenCacheStoreItem*)item;

/*! @return An array of ADTokenCacheStoreItem(s) for all the access tokens store in this keychain item */
- (NSArray*)allItems;

@end
