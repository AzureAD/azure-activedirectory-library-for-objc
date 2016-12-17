//
//  ADAuthorityValidationRequest.h
//  ADAL
//
//  Created by Jason Kim on 12/15/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADAuthorityValidationRequest : NSObject


+ (void)requestAuthorityValidationForAuthority:(NSString *)authority
                              trustedAuthority:(NSString *)trustedAuthority
                                       context:(id<ADRequestContext>)context
                               completionBlock:(void (^)(id response, ADAuthenticationError *error))completionBlock;

@end
