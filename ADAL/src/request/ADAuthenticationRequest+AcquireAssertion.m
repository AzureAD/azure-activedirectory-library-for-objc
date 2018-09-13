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

#import "ADAuthenticationContext+Internal.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCacheItem+Internal.h"

@implementation ADAuthenticationRequest (AcquireAssertion)

- (NSString*)assertionTypeString
{
    if(_assertionType == AD_SAML1_1)
    {
        return MSID_OAUTH2_SAML11_BEARER_VALUE;
    }
    
    if(_assertionType == AD_SAML2)
    {
        return MSID_OAUTH2_SAML2_BEARER_VALUE;
    }
    
    return nil;
}

// Generic OAuth2 Authorization Request, obtains a token from a SAML assertion.
- (void)requestTokenByAssertion:(MSIDTokenResponseCallback)completionBlock
{
    [self ensureRequest];
    NSUUID* correlationId = [_requestParams correlationId];
    MSID_LOG_INFO(_requestParams, @"Requesting token from SAML Assertion.");
    MSID_LOG_INFO_PII(_requestParams, @"Requesting token from SAML Assertion. clientId: %@ resource: %@", _requestParams.clientId, _requestParams.resource);
    
    NSData *encodeData = [_samlAssertion dataUsingEncoding:NSUTF8StringEncoding];
    NSString *base64String = [encodeData base64EncodedStringWithOptions:0];

    NSString* assertionType = [self assertionTypeString];
    if (!assertionType)
    {
        ADAuthenticationError* error = [ADAuthenticationError invalidArgumentError:@"Unrecognized assertion type."
                                                                     correlationId:correlationId];
        completionBlock(nil, error);
        return;
    }
    
    NSMutableDictionary *request_data = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                         assertionType, MSID_OAUTH2_GRANT_TYPE,
                                         base64String, MSID_OAUTH2_ASSERTION,
                                         [_requestParams clientId], MSID_OAUTH2_CLIENT_ID,
                                         [_requestParams resource], MSID_OAUTH2_RESOURCE,
                                         MSID_OAUTH2_SCOPE_OPENID_VALUE, MSID_OAUTH2_SCOPE,
                                         nil];
    [self executeRequest:request_data
              completion:completionBlock];
}

@end
