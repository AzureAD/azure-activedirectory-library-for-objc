//
//  ADPolicyItem.h
//  ADALiOS
//
//  Created by Brandon Werner on 9/9/15.
//  Copyright © 2015 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADPolicyItem : NSObject

@property (strong) NSString* policyName;
@property (strong) NSString* policyID;

+(id) getInstance;

@end
