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
#import "ADWebRequest.h"
#import "ADClientMetrics.h"
#import "ADWebResponse.h"
#import "ADAuthenticationSettings.h"
#import "ADWebAuthController.h"
#import "ADWebAuthController+Internal.h"
#import "ADHelpers.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADWebAuthRequest.h"
#import "NSString+ADURLExtensions.h"
#import "MSIDDeviceId.h"
#import "MSIDAADV1Oauth2Factory.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDRefreshToken.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDClientCapabilitiesUtil.h"


@implementation ADAuthenticationRequest (WebRequest)

- (void)executeRequest:(NSDictionary *)request_data
            completion:(MSIDTokenResponseCallback)completionBlock
{
    NSString *authority = [NSString msidIsStringNilOrBlank:_cloudAuthority] ? _context.authority : _cloudAuthority;
    NSString* urlString = [authority stringByAppendingString:MSID_OAUTH2_TOKEN_SUFFIX];
    ADWebAuthRequest* req = [[ADWebAuthRequest alloc] initWithURL:[NSURL URLWithString:urlString]
                                                          context:_requestParams];
    [req setRequestDictionary:request_data];
    [req setAppRequestMetadata:_requestParams.appRequestMetadata];

    [req sendRequest:^(ADAuthenticationError *error, NSDictionary *response)
     {
         if (error)
         {
             completionBlock(nil, error);
             [req invalidate];
             return;
         }

         MSIDAADV1Oauth2Factory *factory = [MSIDAADV1Oauth2Factory new];

         NSError *msidError = nil;
         MSIDTokenResponse *tokenResponse = [factory tokenResponseFromJSON:response context:nil error:&msidError];

         if (!tokenResponse)
         {
             ADAuthenticationError *adError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError];
             completionBlock(nil, adError);
         }
         else
         {
             completionBlock(tokenResponse, nil);
         }
         
         [req invalidate];
     }];
}

- (NSString *)getRefreshTokenForRequest
{
    if (![NSString msidIsStringNilOrBlank:_refreshToken])
    {
        return _refreshToken;
    }
    else
    {
        NSError *refreshTokenError = nil;
        MSIDRefreshToken *refreshTokenItem = [self.tokenCache getRefreshTokenWithAccount:_requestParams.account
                                                                            familyId:nil
                                                                       configuration:_requestParams.msidConfig
                                                                             context:_requestParams
                                                                               error:&refreshTokenError];

         // FRT is more likely to be valid as it gets refreshed if any app in the family uses it, so try to use the FRT instead
        if (!refreshTokenItem || ![NSString msidIsStringNilOrBlank:[refreshTokenItem familyId]])
        {
            NSError *msidFRTError = nil;
            NSString *familyId = [NSString msidIsStringNilOrBlank:[refreshTokenItem familyId]] ? @"1" : [refreshTokenItem familyId];
            MSIDRefreshToken *frtItem = [self.tokenCache getRefreshTokenWithAccount:_requestParams.account
                                                                                familyId:familyId
                                                                           configuration:_requestParams.msidConfig
                                                                                 context:_requestParams
                                                                                   error:&msidFRTError];
            if (frtItem && !msidFRTError)
            {
                refreshTokenItem = frtItem;
                refreshTokenError = nil;
            }
        }

        MSID_LOG_VERBOSE(_requestParams, @"Retrieve refresh token from cache for web view: %@, error code: %ld", _PII_NULLIFY(refreshTokenItem), (long)refreshTokenError.code);
        return [refreshTokenItem refreshToken];
    }

    return nil;
}

//Requests an OAuth2 code to be used for obtaining a token:
- (void)requestCode:(MSIDAuthorizationCodeCallback)completionBlock
{
    THROW_ON_NIL_ARGUMENT(completionBlock);
    [self ensureRequest];
    
    MSID_LOG_VERBOSE(_requestParams, @"Requesting authorization code");
    MSID_LOG_VERBOSE_PII(_requestParams, @"Requesting authorization code for resource: %@", _requestParams.resource);

    NSString *refreshToken = nil;
    if (_promptBehavior == AD_PROMPT_AUTO && [_context useRefreshTokenForWebview])
    {
        refreshToken = [self getRefreshTokenForRequest];
    }

    [ADWebAuthController startWithRequest:_requestParams promptBehavior:_promptBehavior refreshToken:refreshToken context:_context completion:^(MSIDWebviewResponse *response, NSError *error) {
        
        if (error)
        {
            completionBlock(nil, [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:error]);
            return;
        }
        
        completionBlock(response, nil);
    }];
}

@end
