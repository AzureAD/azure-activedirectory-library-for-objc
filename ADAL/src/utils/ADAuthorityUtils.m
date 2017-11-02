//
//  ADAuthorityUtils.m
//  ADAL
//
//  Created by Sergey Demchenko on 11/1/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

#import "ADAuthorityUtils.h"

static NSSet<NSString *> *s_trustedHostList;

@implementation ADAuthorityUtils

+ (void)initialize
{
    s_trustedHostList = [NSSet setWithObjects: @"login.windows.net",
                         @"login.chinacloudapi.cn",
                         @"login-us.microsoftonline.com",
                         @"login.cloudgovapi.us",
                         @"login.microsoftonline.com",
                         @"login.microsoftonline.de", nil];
}

#pragma mark - Public

+ (BOOL)isKnownHost:(NSURL *)url
{
    return [s_trustedHostList containsObject:url.host.lowercaseString];
}

@end
