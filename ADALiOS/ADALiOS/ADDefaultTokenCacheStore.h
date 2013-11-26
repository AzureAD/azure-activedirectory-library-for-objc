// Created by Boris Vidolov on 10/18/13.
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
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import <ADALiOS/ADTokenCacheStoring.h>

/*! The default implementation of ADTokenCacheStoring. The implementation
 is thread-safe and implemented with @synchronized on the internal storage.
 A faster implementation would be to use read-write locks, but these are
 restricted to POSIX threads only. */
@interface ADDefaultTokenCacheStore : NSObject<ADTokenCacheStoring>
{
    @protected
    /*The internal implementation is a dictionary of dictionaries
     The mCache below has one dictionary for each token cache key
     The inner dictionary is has an additional key by userId to retrieve
     the token cache store items. */
    NSMutableDictionary* mCache;
    
    //The next variables are used for cache persistence
    NSString* mLastArchiveFile;//The last file, where the cache was successfully persisted.
    //Alignment below is needed for the atomic operations:
    __declspec(align(8)) volatile int64_t mCurrenRevision;//The current revision of the cache. Incremented each time the cache is modified.
    __declspec(align(8)) volatile int64_t mArchivedRevision;//The last persisted version of the cache. Set to MAX_LONG_LONG during initialization of the object.
    __declspec(align(8)) volatile int mPersistingQueued;//Set to 1 if the persisting task is already in the queue.
}

/*! Return a copy of all items. The array will contain ADTokenCacheStoreItem objects, 
 containing all of the cached information.*/
-(NSArray*) allItems;

/*! Extracts the key from the item properties. If the item for the key exists, the method removes it. If the item is not in the cache, the method won't do anything. The error (if specified) is filled
 when the passed item doesn't have valid key elements. */
-(void) removeItem: (ADTokenCacheStoreItem*) item
             error: (ADAuthenticationError* __autoreleasing*) error;

/*! Returns the static instance of the token cache store. This instance should be used, instead
 of creating a new one. The initializer of this object will throw an exception */
+(ADDefaultTokenCacheStore*) sharedInstance;

/*! The method checks if the cache has been modified since the last archiving operation and archives
 it synchronously if not. The method is useful to ensure that the cache is persisted when the application
 is about to close.
 The cache is stored to 'defaultTokenCacheStoreLocation', specified in the settings.
 @param error: Optional. if archiving is needed, but the cache cannot be stored to the specified file location, the method
 will use this parameter to fill the error. If this parameter is nil, the error will not be reported.
 @result The method returns YES if the cache persistence is up to date or successfully updated.
 */
-(BOOL) ensureArchived: (ADAuthenticationError* __autoreleasing *) error;

@end

