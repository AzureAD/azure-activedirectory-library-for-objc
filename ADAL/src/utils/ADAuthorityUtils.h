//
//  ADAuthorityUtils.h
//  ADAL
//
//  Created by Sergey Demchenko on 11/1/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADAuthorityUtils : NSObject

+ (BOOL)isKnownHost:(NSString *)string;

@end
