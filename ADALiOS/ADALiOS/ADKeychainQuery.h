//
//  ADKeychainQuery.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 7/12/15.
//  Copyright (c) 2015 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADKeychainQuery : NSObject
{
    CFMutableDictionaryRef _cfmdKeychainQuery;
}

- (id)init;

- (void)setServiceKey:(NSString*)serviceKey;
- (void)setAccessGroup:(NSString*)accessGroup;
- (void)setUserId:(NSString*)userId;
- (void)setCopyData;

- (CFDictionaryRef)queryDictionary;

@end
