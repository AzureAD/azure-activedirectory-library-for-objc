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


#import <Foundation/Foundation.h>

@class MSIDLegacySingleResourceToken;
@class MSIDRefreshToken;
@class MSIDBaseToken;
@protocol MSIDRefreshableToken;
@class MSIDLegacyTokenCacheAccessor;

@interface ADAcquireTokenSilentHandler : NSObject
{
    ADRequestParameters *_requestParams;
    
    MSIDRefreshToken *_mrrtItem;
    MSIDLegacySingleResourceToken *_extendedLifetimeAccessTokenItem; //store valid AT in terms of ext_expires_in (if find any)
    
    // We only return underlying errors from the MRRT Result, because the FRT is a
    // "best attempt" method, which is not necessarily tied to the client ID we're
    // trying, so the MRRT error will be more accurate.
    ADAuthenticationResult *_mrrtResult;
    
    BOOL _attemptedFRT;
}

+ (ADAcquireTokenSilentHandler *)requestWithParams:(ADRequestParameters *)requestParams
                                        tokenCache:(MSIDLegacyTokenCacheAccessor *)tokenCache;

- (void)getToken:(ADAuthenticationCallback)completionBlock;

// Obtains an access token from the passed refresh token. If "cacheItem" is passed, updates it with the additional
// information and updates the cache
- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                         cacheItem:(MSIDBaseToken<MSIDRefreshableToken> *)cacheItem
                  useOpenidConnect:(BOOL)useOpenidConnect
                   completionBlock:(ADAuthenticationCallback)completionBlock;

@end
