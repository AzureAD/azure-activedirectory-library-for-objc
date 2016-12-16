// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


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
