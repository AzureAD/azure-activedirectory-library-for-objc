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

#import "ADAuthorityValidationResponse.h"
#import "ADOAuth2Constants.h"

@implementation ADAuthorityValidationResponse

+ (instancetype)responseWithJSON:(NSDictionary *)jsonResponse
                         context:(id<ADRequestContext>)context
{
    ADAuthorityValidationResponse *response = [ADAuthorityValidationResponse new];
    
    NSString* error = jsonResponse[@"error"];
    if (![NSString adIsStringNilOrBlank:error])
    {
        NSString* errorDetails = [jsonResponse objectForKey:OAUTH2_ERROR_DESCRIPTION];
        errorDetails = errorDetails ? errorDetails : [NSString stringWithFormat:@"The authority validation server returned an error. - %@", error];
        
        response->_error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION
                                                       protocolCode:error
                                                       errorDetails:errorDetails
                                                      correlationId:context.correlationId];
        return response;
    }
    
    response->_validated = YES;
    response->_aliases = jsonResponse[@"aliases"];
    response->_preferredCacheHost = jsonResponse[@"preferred_cache"];
    response->_preferredNetworkHost = jsonResponse[@"preferred_network"];
    
    return response;
}

+ (instancetype)invalidResponse
{
    ADAuthorityValidationResponse *response = [ADAuthorityValidationResponse new];
    return response;
}

@end
