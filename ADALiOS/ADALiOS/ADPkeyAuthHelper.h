//
//  ADPkeyAuthHelper.h
//  ADALiOS
//
//  Created by Kanishk Panwar on 7/29/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RegistrationInformation.h"

@interface ADPkeyAuthHelper : NSObject

+ (NSString*) createDeviceAuthResponse:(NSString*) authorizationServer
                         challengeData:(NSMutableDictionary*) challengeData;

@end
