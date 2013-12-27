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

#import "ADALiOS.h"
#import "ADDefaultTokenCacheStore.h"
#import "ADAuthenticationSettings.h"
#import "ADDefaultTokenCacheStorePersistance.h"
#import <libkern/OSAtomic.h>

static NSString* const missingUserSubstitute = @"9A1BE88B-F078-4559-A442-35111DFA61F0";
const uint64_t MAX_REVISION = LONG_LONG_MAX;
const int16_t UPPER_VERSION = 1;
const int16_t LOWER_VERSION = 0;

@implementation ADDefaultTokenCacheStore

-(id) init
{
    //Throws unrecognized selector. This function should not be called.
    [super doesNotRecognizeSelector:_cmd];
    return self;
}

-(id) initInternal
{
    self = [super init];
    if (self)
    {
        mCache = [NSMutableDictionary new];
    }
    return self;
}

+(ADDefaultTokenCacheStore*) sharedInstance
{
    API_ENTRY;
    static ADDefaultTokenCacheStore* defaultTokenCacheStore;
    static dispatch_once_t once;
    @synchronized(self)//Without this one thread may get a nil instance.
    {
        _dispatch_once(&once, ^()
        {
            //The code in this block will execute only upon the first request of the instance:
            defaultTokenCacheStore = [[ADDefaultTokenCacheStore alloc] initInternal];
            
            NSString* filePath = [[ADAuthenticationSettings sharedInstance] defaultTokenCacheStoreLocation];
            NSFileManager* fileManager = [NSFileManager defaultManager];
            NSString* logMessage = [NSString stringWithFormat:@"File: %@", filePath];
            if (![NSString isStringNilOrBlank:filePath])
            {
                BOOL isDirectory;
                if ([fileManager fileExistsAtPath:filePath isDirectory:&isDirectory] && !isDirectory)
                {
                    defaultTokenCacheStore->mArchivedRevision = MAX_REVISION;//Avoid resaving while loading
                    if ([defaultTokenCacheStore addInitialCacheItemsFromFile:filePath])
                    {
                        defaultTokenCacheStore->mLastArchiveFile = filePath;
                        //Initialize to >0, so that the contents will be stored if the developer
                        //changes the file location (in which case mArchivedRevision is set to 0);
                        defaultTokenCacheStore->mCurrenRevision = 1;
                    }
                    defaultTokenCacheStore->mArchivedRevision = defaultTokenCacheStore->mCurrenRevision;//Synchronize the two.
                    AD_LOG_INFO(@"Successfully loaded the cache.", logMessage);
                }
                else
                {
                    AD_LOG_INFO(@"No persisted cache found.", logMessage);
                }
            }
            else
            {
                AD_LOG_VERBOSE(@"Nil or empty token cache file set.", logMessage);
            }
        });
    }
    return defaultTokenCacheStore;
}

//Returns YES, if the cache needs to be persisted or false, if the file already contains the latest version:
-(BOOL) needsPersistenceWithFile: (NSString*) filePath
                           error: (ADAuthenticationError *__autoreleasing *) error
{
    BOOL modified = NO;
    if (![filePath isEqualToString:mLastArchiveFile])
    {
        //Archiving requested to a new file, always archive there:
        NSString* message = [NSString stringWithFormat:@"The perisistence file has been changed from :'%@' to '%@'", mLastArchiveFile, filePath];
        AD_LOG_VERBOSE(@"Cache persistence file changed.", message);
        mArchivedRevision = 0;//New file, persist unless the cache was never touched or loaded.
    }
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

-(BOOL) ensureArchived: (ADAuthenticationError *__autoreleasing *) error
{
    API_ENTRY;

    //The lock below guards only the file read/write operations. In general,
    //all of the normal cache storing/reading should be working while serialization
    //the only exception is the short time when this method extracts a flat list
    //of the cache contents.
    @synchronized (self)
    {
        NSString* filePath = [[ADAuthenticationSettings sharedInstance] defaultTokenCacheStoreLocation];
        if ([NSString isStringNilOrBlank:filePath])
        {
            //Nil or blank file.
            //We want to log the error only the first time we attempt the file or if the developer explicitly asked for it:
            if (error || ![filePath isEqualToString:mLastArchiveFile])
            {
                NSString* errorMessage = [NSString stringWithFormat:@"Invalid or empty file name supplied for the token cache store persistence: %@", filePath];
                //Note that this will also log the error:
                ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                         protocolCode:nil
                                                                                         errorDetails:errorMessage];
                mLastArchiveFile = filePath;//Avoid reporting this error again.
                if (error)
                {
                    *error = toReport;
                }
            }

            return NO;//Bad path
        }
        
        if (![self needsPersistenceWithFile:filePath error:error])
        {
            AD_LOG_VERBOSE(@"No need for cache persistence.", @"The cache has not been updated since the last persistence.");
            return YES;
        }
        
        int64_t snapShotRevision = 0;
        //This is the only operation that locks the cache (internally in the call below).
        NSArray* allItems = [self allItemsWithRevision:&snapShotRevision];
        ADDefaultTokenCacheStorePersistance* serialization =
            [[ADDefaultTokenCacheStorePersistance alloc] initWithUpperVersion:UPPER_VERSION
                                                                 lowerVersion:LOWER_VERSION
                                                                   cacheItems:allItems];
        NSDate* startWriting = [NSDate dateWithTimeIntervalSinceNow:0];
        if ([NSKeyedArchiver archiveRootObject:serialization toFile:filePath])
        {
            mArchivedRevision = snapShotRevision;//The revision that we just read
            mLastArchiveFile = filePath;
            double archivingTime = -[startWriting timeIntervalSinceNow];//timeIntervalSinceNow returns negative value
            NSString* message = [NSString stringWithFormat:@"The cache was successfully persisted to: '%@', revision: %lld, took: %f seconds.", filePath, mArchivedRevision, archivingTime];
            AD_LOG_VERBOSE(@"Cache persisted.", message);
            
            NSFileManager* fileManager = [NSFileManager defaultManager];
            NSError* attributesError;
            BOOL encrypted = [fileManager setAttributes:<#(NSDictionary *)#> ofItemAtPath:filePath error:&attributesError];
            
            
            return YES;
        }
        else
        {
            NSString* errorMessage = [NSString stringWithFormat:@"Failed to persist to file: %@", filePath];
            //Note that this will also log the error:
            ADAuthenticationError* toReport = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_CACHE_PERSISTENCE
                                                                                     protocolCode:nil
                                                                                     errorDetails:errorMessage];
            if (error)
            {
                *error = toReport;
            }
            return NO;
        }
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
        AD_LOG_WARN(@"getItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey");
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
        AD_LOG_WARN(@"removeItemWithKey called passing nil key", @"At ADDefaultTokenCacheStore::removeItemWithKey");
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

//Reads the passed file and adds its contents to the cache. Returns YES if any items have been added.
//Important: suspends serialization for the added items, as this function is expected to be called form
//the initializer of the cache.
-(BOOL) addInitialCacheItemsFromFile: (NSString*) fileName
{
    ADDefaultTokenCacheStorePersistance* serialization;
    NSDate* startReading = [NSDate dateWithTimeIntervalSinceNow:0];
    @synchronized (self)//File lock, just in case
    {
        serialization = [NSKeyedUnarchiver unarchiveObjectWithFile:fileName];
    }
    if (!serialization || ![serialization isKindOfClass:[ADDefaultTokenCacheStorePersistance class]])
    {
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"Cannot read the file: %@", fileName];
        //This will also log the error:
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT protocolCode:nil errorDetails:message];
        return NO;
    }
    
    if (serialization->upperVersion > UPPER_VERSION)
    {
        //A new, incompatible version of the cache is stored, ignore the cache:
        //The userId should be valid:
        NSString* message = [NSString stringWithFormat:@"The version (%d.%d) of the cache file is not supported. File: %@",
                             serialization->upperVersion, serialization->lowerVersion, fileName];
        //This will also log the error:
        [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_BAD_CACHE_FORMAT protocolCode:nil errorDetails:message];
        return NO;
    }
    
    uint numAdded = 0;

    @synchronized (mCache)//Just in case, avoid other operations on the cache while loading
    {
        for(ADTokenCacheStoreItem* item in serialization->cacheItems)
        {
            if (![item isKindOfClass:[ADTokenCacheStoreItem class]])
            {
                //The userId should be valid:
                NSString* message = [NSString stringWithFormat:@"Bad inner objects. Cannot read the file: %@", fileName];
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
    NSString* log = [NSString stringWithFormat:@"Finished reading of the persisted cache. Version: (%d.%d); Took: %f seconds; File: %@",
                     serialization->upperVersion, serialization->lowerVersion, readingTime, fileName];
    AD_LOG_VERBOSE(@"Token Cache Store Persistence", log);

    return numAdded > 0;
}

@end
