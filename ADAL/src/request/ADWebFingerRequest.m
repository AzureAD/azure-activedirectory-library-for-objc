//
//  ADWebFingerRequest.m
//  ADAL
//
//  Created by Jason Kim on 12/14/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import "ADWebFingerRequest.h"
#import "ADWebAuthRequest.h"
#import "ADOAuth2Constants.h"

// First argument is the authentication endpoint and the second is the authority to check against.
static NSString *const s_kWebFingerConstructor = @"https://%@/.well-known/webfinger?resource=%@";

@implementation ADWebFingerRequest

+ (void)requestWebFinger:(NSString *)authenticationEndpoint
               authority:(NSString *)authority
                 context:(id<ADRequestContext>)context
         completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock
{
    NSURL *fullUrl = [NSURL URLWithString:authenticationEndpoint.lowercaseString];
    
    NSURL *url = [NSURL URLWithString:
                  [NSString stringWithFormat:s_kWebFingerConstructor, fullUrl.host, authority]];
    
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
