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

@implementation ADDrsDiscoveryRequest

+ (void)requestDrsDiscoveryForDomain:(NSString *)domain
                            adfsType:(AdfsType)type
                             context:(id<MSIDRequestContext>)context
                     requestMetadata:(NSDictionary *)metadata
                     completionBlock:(void (^)(id result, ADAuthenticationError *error))completionBlock
{
    NSURL *url = [self urlForDrsDiscoveryForDomain:domain adfsType:type];
    
    ADWebAuthRequest *webRequest = [[ADWebAuthRequest alloc] initWithURL:url context:context];
    [webRequest setIsGetRequest:YES];
    [webRequest setAcceptOnlyOKResponse:YES];
    [webRequest setRequestMetadata:metadata];
    
    [webRequest sendRequest:^(ADAuthenticationError *error, NSMutableDictionary *response)
    {
        if (error)
        {
            completionBlock(nil, error);
        }
        else
        {
            completionBlock(response, nil);
        }
        
        [webRequest invalidate];
    }];
}

+ (NSURL *)urlForDrsDiscoveryForDomain:(NSString *)domain adfsType:(AdfsType)type
{
    if (type == AD_ADFS_ON_PREMS)
    {
        return [NSURL URLWithString:
                [NSString stringWithFormat:@"https://enterpriseregistration.%@/enrollmentserver/contract?api-version=1.0", domain.lowercaseString]];
    }
    else if (type == AD_ADFS_CLOUD)
    {
        return [NSURL URLWithString:
                [NSString stringWithFormat:@"https://enterpriseregistration.windows.net/%@/enrollmentserver/contract?api-version=1.0", domain.lowercaseString]];
    }
    else
    {
        @throw @"unrecognized type";
    }
}

@end
