//
//  OpenSSLHelper.h
//  ADALiOS
//
//  Created by Kanishk Panwar on 8/17/14.
//  Copyright (c) 2014 MS Open Tech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OpenSSLHelper : NSObject

+ (NSString*) getCertificateIssuer:(NSData*)certificateData;

@end
