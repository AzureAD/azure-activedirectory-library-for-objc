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

#import "ADTokenCacheAccessor.h"

@interface ADAuthenticationRequest (TokenCaching)

//Checks the cache for item that can be used to get directly or indirectly an access token.
//Checks the multi-resource refresh tokens too.
- (ADTokenCacheItem*)findCacheItemWithKey:(ADTokenCacheKey *)key
                                   userId:(ADUserIdentifier *)userId
                            correlationId:(NSUUID *)correlationId
                                    error:(ADAuthenticationError * __autoreleasing *)error;

- (ADTokenCacheItem *)findFamilyItemForUser:(ADUserIdentifier *)userIdentifier
                              correlationId:(NSUUID *)correlationId
                                      error:(ADAuthenticationError * __autoreleasing *)error;

//Stores the result in the cache. cacheItem parameter may be nil, if the result is successfull and contains
//the item to be stored.
- (void)updateCacheToResult:(ADAuthenticationResult*)result
                  cacheItem:(ADTokenCacheItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
       requestCorrelationId:(NSUUID*)requestCorrelationId;
- (void)updateCacheToResult:(ADAuthenticationResult*)result
              cacheInstance:(id<ADTokenCacheAccessor>)tokenCacheStoreInstance
                  cacheItem:(ADTokenCacheItem*)cacheItem
           withRefreshToken:(NSString*)refreshToken
       requestCorrelationId:(NSUUID*)requestCorrelationId;

- (ADTokenCacheItem *)extractCacheItemWithKey:(ADTokenCacheKey *)key
                                       userId:(ADUserIdentifier *)userId
                                correlationId:(NSUUID *)correlationId
                                        error:(ADAuthenticationError * __autoreleasing *)error;

@end
