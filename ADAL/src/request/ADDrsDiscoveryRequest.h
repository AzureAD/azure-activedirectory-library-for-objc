//
//  ADDrsDiscoveryRequest.h
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

/*!
 For ADFS authority, type can be specified to be on-prems, or cloud.
  */
typedef enum
{
    /*! The SDK will try DRS discovery service for on-prems. */
    AD_ADFS_ON_PREMS,
    
    /*! The SDK will try DRS discovery service for cloud. */
    AD_ADFS_CLOUD
    
} AdfsType;

@interface ADDrsDiscoveryRequest : NSObject

+ (void)requestDrsDiscoveryForDomain:(NSString *)domain
                            adfsType:(AdfsType)type
                             context:(id<ADRequestContext>)context
                     completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock;

@end
