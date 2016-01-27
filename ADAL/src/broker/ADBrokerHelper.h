//
//  ADBrokerHelper.h
//  ADAL
//
//  Created by Ryan Pangrle on 1/26/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADBrokerHelper : NSObject

+ (BOOL)canUseBroker;
+ (BOOL)invokeBroker:(NSDictionary *)brokerParams;
+ (BOOL)promptBrokerInstall:(NSDictionary *)brokerParams;

@end
