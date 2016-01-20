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

#import "ADTokenCache.h"
#import "ADTokenCacheAccessor.h"

@interface ADTokenCache (Internal) <ADTokenCacheAccessor>

- (void)updateStorage;
- (BOOL)checkCache:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;
- (BOOL)validateCache:(nullable NSDictionary *)dict
                error:(ADAuthenticationError * __nullable  __autoreleasing * __nullable)error;

- (nullable NSArray<ADTokenCacheItem *> *)getItemsWithKey:(nullable ADTokenCacheStoreKey *)key
                                                   userId:(nullable NSString *)userId
                                                    error:(ADAuthenticationError * __nullable __autoreleasing * __nullable)error;

@end

