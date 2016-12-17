//
//  ADAuthorityValidationRequest.m
//  ADAL
//
//  Created by Jason Kim on 12/15/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADAuthorityValidationRequest.h"
#import "ADOAuth2Constants.h"
#import "NSDictionary+ADExtensions.h"
#import "ADWebAuthRequest.h"

static NSString* const s_kApiVersionKey = @"api-version";
static NSString* const s_kApiVersion = @"1.0";
static NSString* const s_kAuthorizationEndPointKey = @"authorization_endpoint";

@implementation ADAuthorityValidationRequest

+ (void)requestAuthorityValidationForAuthority:(NSString *)authority
                              trustedAuthority:(NSString *)trustedAuthority
                                       context:(id<ADRequestContext>)context
                               completionBlock:(void (^)(id response, ADAuthenticationError *error))completionBlock
{
    NSString *authorizationEndpoint = [authority stringByAppendingString:OAUTH2_AUTHORIZE_SUFFIX];
    NSDictionary *request_data = @{s_kApiVersionKey:s_kApiVersion,
                                   s_kAuthorizationEndPointKey: authorizationEndpoint};
    NSString *endpoint = [NSString stringWithFormat:@"%@/%@?%@",
                           trustedAuthority, OAUTH2_INSTANCE_DISCOVERY_SUFFIX, [request_data adURLFormEncode]];
    
    ADWebAuthRequest *webRequest = [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:endpoint]
                                                                 context:context];
    
    [webRequest setIsGetRequest:YES];
    [webRequest sendRequest:^(NSMutableDictionary *response)
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
