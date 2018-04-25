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
#import "ADTokenCache.h"

#define CURRENT_WRAPPER_CACHE_VERSION 1.0

@class ADAuthenticationError;
@class ADTokenCacheItem;

@interface ADLegacyMacTokenCache : ADTokenCache <ADTokenCacheDataSource>
{
    NSMutableDictionary* _cache;
}

/*! Returns the default cache object using the ADTokenCacheDelegate set in
    ADAuthenticationSettings */
+ (nonnull ADLegacyMacTokenCache *)defaultCache;

- (void)setDelegate:(nullable id<ADTokenCacheDelegate>)delegate;

- (nullable NSData *)serialize;
- (BOOL)deserialize:(nullable NSData*)data
              error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (nullable NSArray<ADTokenCacheItem *> *)allItems:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (BOOL)removeItem:(nonnull ADTokenCacheItem *)item
             error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

- (BOOL)validateCache:(nullable NSDictionary *)dict
                error:(ADAuthenticationError * __nullable  __autoreleasing * __nullable)error;

- (nullable id<ADTokenCacheDelegate>)delegate;

@end
