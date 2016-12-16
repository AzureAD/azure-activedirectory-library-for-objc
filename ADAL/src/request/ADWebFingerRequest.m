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
