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


#import "ADAuthorityValidationRequest.h"
#import "ADWebAuthRequest.h"

static NSString* const s_kApiVersionKey            = @"api-version";
static NSString* const s_kApiVersion               = @AAD_AUTHORITY_VALIDATION_API_VERSION;
static NSString* const s_kAuthorizationEndPointKey = @"authorization_endpoint";

@implementation ADAuthorityValidationRequest

+ (void)requestMetadataWithAuthority:(NSString *)authority
                         trustedHost:(NSString *)trustedHost
                             context:(id<MSIDRequestContext>)context
                     completionBlock:(void (^)(NSDictionary *response, ADAuthenticationError *error))completionBlock
{
    NSURL *endpoint = [self urlForAuthorityValidation:authority trustedHost:trustedHost];
    ADWebAuthRequest *webRequest = [[ADWebAuthRequest alloc] initWithURL:endpoint
                                                                 context:context];
    
    [webRequest setIsGetRequest:YES];
    [webRequest setAppRequestMetadata:context.appRequestMetadata];

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

+ (NSURL *)urlForAuthorityValidation:(NSString *)authority trustedHost:(NSString *)trustedHost
{
    //TODO: Replace with MSIDAADEndpointProvider method once available
    NSString *authorizationEndpoint = [authority.lowercaseString stringByAppendingString:MSID_OAUTH2_AUTHORIZE_SUFFIX];
    NSDictionary *request_data = @{s_kApiVersionKey:s_kApiVersion,
                                   s_kAuthorizationEndPointKey: authorizationEndpoint};
    
    NSString *endpoint = [NSString stringWithFormat:@"https://%@/%@?%@",
                          trustedHost, MSID_OAUTH2_INSTANCE_DISCOVERY_SUFFIX, [NSString msidWWWFormURLEncodedStringFromDictionary:request_data]];
    
    return [NSURL URLWithString:endpoint];
}

@end
