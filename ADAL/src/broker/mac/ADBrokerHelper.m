//
//  ADBrokerHelper.m
//  ADAL
//
//  Created by Ryan Pangrle on 1/26/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADBrokerHelper.h"

// TODO: Mac Broker Implementation!

@implementation ADBrokerHelper

+ (BOOL)canUseBroker
{
    return NO;
}

+ (BOOL)invokeBroker:(NSDictionary *)brokerParams
{
    (void)brokerParams;
    
    return NO;
}

+ (BOOL)promptBrokerInstall:(NSDictionary *)brokerParams
{
    (void)brokerParams;
    
    return NO;
}

@end
