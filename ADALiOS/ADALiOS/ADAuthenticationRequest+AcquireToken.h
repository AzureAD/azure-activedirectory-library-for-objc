// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

#import "ADAuthenticationRequest.h"

@interface ADAuthenticationRequest (AcquireToken)

- (void)acquireToken:(ADAuthenticationCallback)completionBlock;

// For use after the authority has been validated
- (void)validatedAcquireToken:(ADAuthenticationCallback)completionBlock;

// Bypasses the cache and attempts to request a token from the server, generally called after
// attempts to use cached tokens failed
- (void)requestToken:(ADAuthenticationCallback)completionBlock;

// Generic OAuth2 Authorization Request, obtains a token from an authorization code.
- (void)requestTokenByCode:(NSString*)code
           completionBlock:(ADAuthenticationCallback)completionBlock;

- (void)acquireTokenByRefreshToken:(NSString*)refreshToken
                         cacheItem:(ADTokenCacheStoreItem*)cacheItem
                   completionBlock:(ADAuthenticationCallback)completionBlock;

- (void) validatedAcquireTokenByRefreshToken:(NSString*)refreshToken
                                   cacheItem:(ADTokenCacheStoreItem*)cacheItem
                             completionBlock:(ADAuthenticationCallback)completionBlock;

@end
