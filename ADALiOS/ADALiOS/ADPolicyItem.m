//
//  ADPolicyItem.m
//  ADALiOS
//
//  Created by Brandon Werner on 9/9/15.
//  Copyright © 2015 MS Open Tech. All rights reserved.
//

#import "ADPolicyItem.h"

@implementation ADPolicyItem

+(id) getInstance
{
    static ADPolicyItem *instance = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
        NSDictionary *dictionary = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"settings" ofType:@"plist"]];
        instance.policyName = [dictionary objectForKey:@"policyName"];
        instance.policyID = [dictionary objectForKey:@"policyID"];
        
        
    });
    
    return instance;
}

@end
