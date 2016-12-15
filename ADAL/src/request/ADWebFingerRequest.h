//
//  ADWebFingerRequest.h
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADWebFingerRequest : NSObject

+ (void)requestWebFinger:(NSString *)authenticationEndpoint
               authority:(NSString *)authority
                 context:(id<ADRequestContext>)context
         completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock;

@end
