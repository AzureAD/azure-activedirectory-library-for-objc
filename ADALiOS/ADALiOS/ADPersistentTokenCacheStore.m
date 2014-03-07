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

#import "ADPersistentTokenCacheStore.h"
#import "ADAuthenticationSettings.h"
#import "ADDefaultTokenCacheStorePersistance.h"
#import <libkern/OSAtomic.h>
#import "ADUserInformation.h"
#import "ADTokenCacheStoreItem.h"
#import "ADTokenCacheStoreKey.h"

NSString* const missingUserSubstitute = @"9A1BE88B-F078-4559-A442-35111DFA61F0";

static const uint64_t MAX_REVISION = LONG_LONG_MAX;

@implementation ADPersistentTokenCacheStore

@synthesize cacheLocation = mCacheLocation;

-(id) init
{
    //Throws unrecognized selector. This function should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return self;
}

-(id) initWithLocation:(NSString*) cacheLocation
{
#if TARGET_OS_IPHONE
    //Persistence and hence its location is required on mobile platforms (iOS)
    //due to the nature of application lifetime there:
    if ([NSString isStringNilOrBlank:cacheLocation])
    {
        AD_LOG_ERROR_F(@"Bad token cache store location.", AD_ERROR_CACHE_PERSISTENCE, @"Empty or nil cache location specified.");
        return nil;
    }
#endif
    
    self = [super init];
    if (self)
    {
        mCache = [NSMutableDictionary new];
        mCacheLocation = cacheLocation;
        mArchivedRevision = mCurrenRevision = 0;
    }
    return self;
}

//Returns YES, if the cache needs to be persisted or false, if the file already contains the latest version:
-(BOOL) needsPersistenceWithError: (ADAuthenticationError *__autoreleasing *) error
{
    BOOL modified = NO;
    int64_t currentRevision = mCurrenRevision;//The revision that will be used
    if (currentRevision > mArchivedRevision)
        modified = YES;
    else
    {
        //Check if the archived revision is ahead of the in-memory one and raise error in this case:
        if (mArchivedRevision > currentRevision && mArchivedRevision != MAX_REVISION)
        {
            //currentRevision should always be >= mArchivedRevision, unless it is set explicitly to MAX_REVISION during initialization
            NSString* errorMessage = [NSString stringWithFormat:@"Archived revision is ahead of the currentRevision: %llu vs %llu",
                                      mArchivedRevision, mCurrenRevision];
            //Note that this will also log the error:
            ADAuthenticationError* toReport = [ADAuthenticationError unexpectedInternalError:errorMessage];
            if (error)
            {
                *error = toReport;
            }
            //Recover by clearing the invalid archived cache revision and force persisting
            mArchivedRevision = 0;
            modified = YES;
        }
    }
    return modified;
}

//The actual method that persists the items in the cache. It is not intended to be thread-safe
//and thread-safety measures should be applied by the caller. This method may be overriden by
//derived classes to implement different means of asymchronous persistence (file system, keychain, some shared storage, etc.)
-(BOOL) persistWithItems: (NSArray*) flatItemsList
                   error: (ADAuthenticationError *__autoreleasing *) error
{
    [self doesNotRecognizeSelector:_cmd];//Should be overridden by derived classes
    return NO;
}

-(BOOL) ensureArchived: (ADAuthenticationError *__autoreleasing *) error
{
    API_ENTRY;

    //The lock below guards only the file read/write operations. In general,
    //all of the normal cache storing/reading should be working while serialization.
    //The only exception is the short time when this method extracts a flat list
    //of the cache contents.
    @synchronized (self)
    {
        if ([NSString isStringNilOrBlank:self.cacheLocation])
        {
            //Nil or blank file. The initializer does not allow it:
            ADAuthenticationError* toReport = [ADAuthenticationError unexpectedInternalError:@"The token cache store is attempting to store to a nil or empty file name."];
            //We want to log the error only the first time we attempt the file or if the developer explicitly asked for it:
            if (error)
            {
                *error = toReport;
            }

            return NO;//Bad path
        }
        
        if (![self needsPersistenceWithError:error])
        {
            AD_LOG_VERBOSE(@"No need for cache persistence.", @"The cache has not been updated since the last persistence.");
            return YES;
        }
        
        int64_t snapShotRevision = 0;
        //This is the only operation that locks the cache (internally in the call below).
        NSArray* allItems = [self allItemsWithRevision:&snapShotRevision];
        NSDate* startWriting = [NSDate dateWithTimeIntervalSinceNow:0];
        BOOL succeded  = [self persistWithItems:allItems error:error];
        if (succeded)
        {
            double archivingTime = -[startWriting timeIntervalSinceNow];//timeIntervalSinceNow returns negative value
            AD_LOG_VERBOSE_F(@"Cache persisted.", @"The cache was successfully persisted to: '%@', revision: %lld, took: %f seconds.", self.cacheLocation, snapShotRevision, archivingTime);
            
            mArchivedRevision = snapShotRevision;//The revision that we just read
        }
        return succeded;
    }
}

//This method should always be called from within the asynchronous persistence block:
-(void) attemptToArchive
{
    //Task dequeued. Make sure that a further modification of the cache is queued again.
    if ( !OSAtomicCompareAndSwapInt( 1, 0, &mPersistingQueued) )//Done persisting
    {
        //Log the error condition:
        [ADAuthenticationError unexpectedInternalError:@"mPersisting should be true here. attemptToArchive should be called only as responder to dispatch."];
        mPersistingQueued = 0;//Attempt to recover.
    }
    
    //Note that the ensureArchived will check the revisions and if the previous taks already saved the latest, it won't
    //do anything:
    [self ensureArchived:nil];//Ignore the errors 
}

//This internal method should be called each time the cache is modified.
//The method makes sure that the modification will be persisted asynchronously.
-(void) processModification
{
    OSAtomicIncrement64(&mCurrenRevision);
    if (mArchivedRevision != MAX_REVISION)//Avoid persisting during cache initialization
    {
        //If we don't have a task in the queue to persist, enqueue one now
        //Else, the changes will be picked automatically by the enqueued task.
        if (OSAtomicCompareAndSwapInt(0, 1, &mPersistingQueued))
        {
            //Enqueue if a taks is not waiting in the queue already:
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^
            {
                [self attemptToArchive];
            });
        }
    }
}

//Depending on the user information in the item, it may return a unique name,
//to be used in the enclosed dictionary:
+(NSString*) getValidUserFromItem: (ADTokenCacheStoreItem*) item
{
    THROW_ON_NIL_ARGUMENT(item);
    
    if (!item.userInformation || [NSString isStringNilOrBlank:item.userInformation.userId])
    {
        return missingUserSubstitute;
    }
    else
    {
        //If the userId is present, just trim the white space and make it lowercase:
        return [item.userInformation.userId trimmedString].lowercaseString;
    }
}

-(NSArray*) allItemsWithRevision:(int64_t*) revision
{
    //Flattens the internal cache, copies all elements:
    NSMutableArray* items = [NSMutableArray new];
    
    @synchronized(mCache)
    {
        for (NSDictionary* innerDict in mCache.allValues)
        {
            for (ADTokenCacheStoreItem* item in innerDict.allValues)
            {
                [items addObject:[item copy]];//Copy to prevent modification
            }
        }
        if (revision)
        {
            //The current version of the cache. Used for persistence:
            *revision = mCurrenRevision;
        }
    }
    return items;
}

-(NSArray*) allItems
{
    API_ENTRY;
    
    return [self allItemsWithRevision:nil];
}

-(void) addOrUpdateItem: (ADTokenCacheStoreItem*) item
                  error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
    RETURN_ON_NIL_ARGUMENT(item);
    
    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (key)
    {
        @synchronized(mCache)
        {
            NSMutableDictionary* dictionary = [mCache objectForKey:key];
            if (nil == dictionary)
            {
                //No items for this key, just add the inner dictionary:
                dictionary = [NSMutableDictionary new];
                [mCache setObject:dictionary forKey:key];
            }
            //Now set the object in the inner dictionary, indexed by user:
            [dictionary setObject:[item copy]
                           forKey:[self.class getValidUserFromItem:item]];
            [self processModification];
        }//@synchronized
    }
}

-(void) removeItem: (ADTokenCacheStoreItem*) item
             error: (ADAuthenticationError* __autoreleasing*) error
{
    API_ENTRY;
    RETURN_ON_NIL_ARGUMENT(item);

    ADTokenCacheStoreKey* key = [item extractKeyWithError:error];
    if (key)
    {
        //Note that the userId argument can be nil here, if userInformation or userId
        //is nil. In this case, the userId of the matching items will be ignored:
        [self removeItemWithKey:key
                         userId:item.userInformation.userId];
    }
}

-(void) removeAll
{
    API_ENTRY;
    
    @synchronized(mCache)
    {
        if (mCache.count > 0)
        {
            //Remove and schedule persistence if the cache wasn't already empty:
            [mCache removeAllObjects];
            [self processModification];
        }
    }
}

-(ADTokenCacheStoreItem*) getItemWithKey: (ADTokenCacheStoreKey*) key
                                  userId: (NSString *)userId
{
    API_ENTRY;
    if (!key)
    {
        AD_LOG_WARN(@"getItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey:userId");
        return nil;
    }
    @synchronized(mCache)
    {
        NSDictionary* dictionary = [mCache objectForKey:key];
        
        if (nil == dictionary)
        {
            return nil;//Nothing in the cache.
        }
        
        if (userId == nil)
        {
            //First try to find an item with empty user info:
            ADTokenCacheStoreItem* item = [dictionary objectForKey:missingUserSubstitute];
            if (nil != item)
            {
                return [item copy];
            }
            
            //If we have only items with userId, just return the first:
            for(ADTokenCacheStoreItem* innerItem in dictionary.allValues)
            {
                return [innerItem copy];
            }
            return nil;//Just in case
        }
        else
        {
            ADTokenCacheStoreItem* item = [dictionary objectForKey:[[userId trimmedString] lowercaseString]];
            return [item copy];//May return nil, if item is nil
        }
    }//@synchronized
}

-(void) removeItemWithKey: (ADTokenCacheStoreKey*) key
                   userId: (NSString*) userId
{
    API_ENTRY;
    
    if (!key)
    {
        AD_LOG_WARN(@"removeItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey:userId");
        return;
    }
    
    @synchronized(mCache)
    {
        NSMutableDictionary* dictionary = [mCache objectForKey:key];
        if (nil == dictionary)
        {
            return;//Not in the cache
        }
        
        if (!userId)
        {
            if (!dictionary.count)
            {
                AD_LOG_WARN(@"Empty inner dictionary", @"The default cache shouldn't store empty dictionary.");
                return;
            }
            
            //Removed all items, regardless of the user. Items exist, else 'dictionary' would have been nil
            //as we do not store empty inner dictionary objects.
            [mCache removeObjectForKey:key];
            [self processModification];
            return;
        }
        
        NSString* userKey = [[userId trimmedString] lowercaseString];
        if ([dictionary objectForKey:userKey] != nil)
        {
            //The item is present, just remove it:
            [dictionary removeObjectForKey:userKey];
            if (!dictionary.count)
            {
                //Avoid storing of empty dictionary:
                [mCache removeObjectForKey:key];
            }
            [self processModification];
        }
    }
}

-(NSArray*) getItemsWithKey: (ADTokenCacheStoreKey*)key
{
    API_ENTRY;
    NSMutableArray* array = [NSMutableArray new];
    if (!key)
    {
        AD_LOG_WARN(@"getItemsWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey");
        return array;
    }
    
    @synchronized(mCache)
    {
        NSDictionary* dictionary = [mCache objectForKey:key];
        for (ADTokenCacheStoreItem* item in dictionary.allValues)
        {
            [array addObject:[item copy]];
        }
    }
    return array;
}

-(NSArray*) unpersist
{
#if TARGET_OS_IPHONE
    //On the mobile platforms, we need to enforce persistentence, due to the nature of
    //the application lifetimes. We give the option of in-memory, non-persisted cache on the OS X
    //implementations.
    [self doesNotRecognizeSelector:_cmd];//Should be overridden by the derived classes
#endif
    return nil;
}

//Reads the passed file and adds its contents to the cache. Returns YES if any items have been added.
//Important: suspends serialization for the added items, as this function is expected to be called form
//the initializer of the cache.
-(BOOL) addInitialCacheItems
{
    NSDate* startReading = [NSDate dateWithTimeIntervalSinceNow:0];
    NSArray* loadedItems;
    uint numAdded = 0;
    
    @synchronized (self)//File lock, just in case
    {
        mArchivedRevision = MAX_REVISION;//Avoid resaving while loading
        loadedItems = [self unpersist];
        if (!loadedItems)
        {
            mArchivedRevision = mCurrenRevision = 0;
            return NO;
        }
        
        @synchronized (mCache)//Just in case, avoid other operations on the cache while loading
        {
            for(ADTokenCacheStoreItem* item in loadedItems)
            {
                if (![item isKindOfClass:[ADTokenCacheStoreItem class]])
                {
                    //The userId should be valid:
                    NSString* message = [NSString stringWithFormat:@"Bad inner objects, when reading the location: %@",
                                         self.cacheLocation];
                    //This will also log the error:
                    [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT protocolCode:nil errorDetails:message];
                }
                ADAuthenticationError* error;
                [self addOrUpdateItem:item error:&error];//Logs any error internally
                if (!error)
                {
                    //Successfully added
                    ++numAdded;
                }
            }
        }
        double readingTime = -[startReading timeIntervalSinceNow];//timeIntervalSinceNow returns negative value-[
        AD_LOG_VERBOSE_F(@"Token Cache Store Persistence", @"Finished reading of the persisted cache. Took: %f seconds; File: %@",
                         readingTime, self.cacheLocation);
        
        if (numAdded > 0)
        {
            mCurrenRevision = 1;//Used to ensure that some read operation has occurred.
        }
        mArchivedRevision = mCurrenRevision;//Synchronize the two.
    }
    return numAdded > 0;
}

@end
