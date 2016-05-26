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

@interface ADAuthenticationRequest (AcquireAssertion)

- (void)acquireTokenForAssertion:(NSString*)samlAssertion
                   assertionType:(ADAssertionType)assertionType
                 completionBlock:(ADAuthenticationCallback)completionBlock;

/*Attemps to use the cache. Returns YES if an attempt was successful or if an
 internal asynchronous call will proceed the processing. */
- (void)attemptToUseCacheItem:(ADTokenCacheStoreItem*)item
               useToken:(BOOL)useToken
                samlAssertion:(NSString*)samlAssertion
                assertionType:(ADAssertionType)assertionType
              completionBlock:(ADAuthenticationCallback)completionBlock;

// Generic OAuth2 Authorization Request, obtains a token from a SAML assertion.
- (void)requestTokenByAssertion:(NSString *)samlAssertion
                  assertionType:(ADAssertionType)assertionType
                     completion:(ADAuthenticationCallback)completionBlock;

@end
