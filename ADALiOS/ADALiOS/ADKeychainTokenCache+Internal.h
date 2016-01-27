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

#import "ADKeychainTokenCache.h"
#import "ADTokenCacheAccessor.h"

@class ADTokenCacheStoreKey;

@interface ADKeychainTokenCache (Internal) <ADTokenCacheAccessor>

+ (BOOL)checkStatus:(OSStatus)status
            details:(NSString*)details
              error:(ADAuthenticationError* __autoreleasing *)error;

- (NSMutableDictionary *)queryDictionaryForKey:(ADTokenCacheKey *)key
                                        userId:(NSString *)userId
                                    additional:(NSDictionary*)additional;

- (NSString*)keychainKeyFromCacheKey:(ADTokenCacheKey *)itemKey;

/*! This method should *only* be called in test code, it should never be called
    in production code */
- (void)testRemoveAll:(ADAuthenticationError * __autoreleasing *)error;

@end
