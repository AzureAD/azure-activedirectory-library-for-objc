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

@interface ADTokenCacheStorageWrapper : NSObject <ADTokenCacheEnumerator>

- (id)initWithStorage:(id<ADCacheStorageDelegate>)storage;

@end
