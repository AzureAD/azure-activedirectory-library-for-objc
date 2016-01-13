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

#import "ADTokenCacheEnumerator.h"

@interface ADAuthenticationContext (TokenCaching)

//Checks the cache for item that can be used to get directly or indirectly an access token.
//Checks the multi-resource refresh tokens too.
- (ADTokenCacheStoreItem*)findCacheItemWithKey:(ADTokenCacheStoreKey*) key
                                        userId:(ADUserIdentifier*)userId
                                useAccessToken:(BOOL*) useAccessToken
                                         error:(ADAuthenticationError* __autoreleasing*) error;

//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult*)result
                  cacheItem:(ADTokenCacheStoreItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken;
- (void)updateCacheToResult:(ADAuthenticationResult*)result
              cacheInstance:(id<ADTokenCacheEnumerator>)tokenCacheStoreInstance
                  cacheItem:(ADTokenCacheStoreItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken;

- (ADTokenCacheStoreItem*)extractCacheItemWithKey:(ADTokenCacheStoreKey*)key
                                           userId:(ADUserIdentifier*)userId
                                            error:(ADAuthenticationError* __autoreleasing*)error;

@end
