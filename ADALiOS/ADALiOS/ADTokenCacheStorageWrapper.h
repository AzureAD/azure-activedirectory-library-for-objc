//
//  ADTokenCacheStorageWrapper.h
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ADTokenCacheStoring.h"
#import "ADCacheStorage.h"

@interface ADTokenCacheStorageWrapper : NSObject <ADTokenCacheStoring>

- (id)initWithStorage:(id<ADCacheStorage>)storage;

@end
