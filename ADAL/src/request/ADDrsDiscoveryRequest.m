//
//  ADDrsDiscoveryRequest.m
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADDrsDiscoveryRequest.h"
#import "ADWebAuthRequest.h"
#import "ADOAuth2Constants.h"

static NSString *const s_kAdfsCloudDiscovery = @"https://enterpriseregistration.windows.net/%@/enrollmentserver/contract?api-version=1.0";
static NSString *const s_kAdfsOnPremsDiscovery = @"https://enterpriseregistration.%@/enrollmentserver/contract?api-version=1.0";

@implementation ADDrsDiscoveryRequest

+ (void)requestDrsDiscoveryForDomain:(NSString *)domain
                            adfsType:(AdfsType)type
                             context:(id<ADRequestContext>)context
                     completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock
{
    NSURL *url = [NSURL URLWithString:
                  [NSString stringWithFormat: (type == AD_ADFS_ON_PREMS) ? s_kAdfsOnPremsDiscovery : s_kAdfsCloudDiscovery, domain]];
    
    ADWebAuthRequest *webReq = [[ADWebAuthRequest alloc] initWithURL:url context:context];
    [webReq setIsGetRequest:YES];
    [webReq setAcceptOnlyOKResponse:YES];
    
    [webReq sendRequest:^(NSMutableDictionary *response)
    {
        ADAuthenticationError *error = [response objectForKey:AUTH_NON_PROTOCOL_ERROR];

        if (error)
        {
            completionBlock(nil, error);
        }
        else
        {
            completionBlock(response, nil);
        }
    }];
}

@end
