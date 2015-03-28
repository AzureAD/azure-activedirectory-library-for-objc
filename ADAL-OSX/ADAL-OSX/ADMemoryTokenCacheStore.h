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
#import <Foundation/Foundation.h>
#import "ADTokenCacheStoring.h"

@class ADTokenCacheStoreItem;
@class ADAuthenticationError;

/*! The default implementation of ADTokenCacheStoring. The implementation
 is thread-safe and implemented with @synchronized on the internal storage.
 A faster implementation would be to use read-write locks, but these are
 restricted to POSIX threads only.
 The class scheduleds an asynchronous serialization upon modification.
 The actual persistence is implemented by the derived classes.
 */
@interface ADMemoryTokenCacheStore : NSObject<ADTokenCacheStoring>
{
@protected
    /*The internal implementation is a dictionary of dictionaries
     The mCache below has one dictionary for each token cache key
     The inner dictionary is has an additional key by userId to retrieve
     the token cache store items. */
    NSMutableDictionary* mCache;
}

/*! Extracts the key from the item properties. If the item for the key exists, the method removes it. If the item is not in the cache, the method won't do anything. The error (if specified) is filled
 when the passed item doesn't have valid key elements. */
-(void) removeItem: (ADTokenCacheStoreItem*) item
             error: (ADAuthenticationError* __autoreleasing*) error;

@end