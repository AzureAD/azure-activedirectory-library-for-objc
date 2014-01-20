// Created by Boris Vidolov on 10/22/13.
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

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import <ADALiOS/ADPersistentTokenCacheStore.h>
#import <libkern/OSAtomic.h>
#import <ADALiOS/ADAuthenticationSettings.h>

dispatch_semaphore_t sThreadsSemaphore;//Will be signalled when the last thread is done. Should be initialized and cleared in the test.
volatile int32_t sThreadsFinished;//The number of threads that are done. Should be set to 0 at the beginning of the test.
const int sMaxThreads = 10;//The number of threads to spawn
int sThreadsRunTime = 5;//How long the bacground threads would run
static int sPersistenceTimeout = 10;//In seconds

//Some logging constant to help with testing the persistence:
NSString* const sPersisted = @"successfully persisted";
NSString* const sNoNeedForPersistence = @"No need for cache persistence.";
NSString* const sFileNameEmpty = @"Invalid or empty file name";

@interface ADDefaultTokenCacheStoreTests : XCTestCase
{
    ADPersistentTokenCacheStore* mStore;
    NSMutableDictionary* mCache;
}
@end

@interface ADPersistentTokenCacheStore(Test)

-(NSMutableDictionary*) internalCache;
//The next variables are used for cache persistence
-(NSString*) getLastArchiveFile;

-(int64_t) getCurrenRevision;
-(void) setCurrentRevision: (int64_t) newValue;

-(int64_t) getArchivedRevision;
-(void) setArchivedRevision: (int64_t) newValue;

-(BOOL) addInitialCacheItems;

@end

//Avoid warnings for incomplete implementation, as the methods are actually implemented, just not in the category:
#pragma clang diagnostic ignored "-Wincomplete-implementation"
@implementation ADPersistentTokenCacheStore(Test)


-(NSMutableDictionary*) internalCache
{
    return mCache;
}

-(int64_t) getCurrenRevision
{
    return mCurrenRevision;
}
-(void) setCurrentRevision: (int64_t) newValue
{
    mCurrenRevision = newValue;
}

-(int64_t) getArchivedRevision
{
    return mArchivedRevision;
}

-(void) setArchivedRevision: (int64_t) newValue
{
    mArchivedRevision = newValue;
}

@end

@implementation ADDefaultTokenCacheStoreTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin];
    
    mStore = (ADPersistentTokenCacheStore*)[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    XCTAssertTrue([mStore isKindOfClass:[ADPersistentTokenCacheStore class]]);
    mCache = [mStore internalCache];
    XCTAssertNotNil(mCache, "The internal cache should be set.");
    [mCache removeAllObjects];//Start clean before each test
}

- (void)tearDown
{
    mStore = nil;
    mCache = nil;
    
    [self adTestEnd];
    [super tearDown];
}

//A wrapper around addOrUpdateItem, when called synchronously from one
//thread only.
-(void) syncAddOrUpdateItem: (ADTokenCacheStoreItem*) item
{
    int64_t revision = [mStore getCurrenRevision];
    XCTAssertTrue(revision >= [mStore getArchivedRevision]);
    ADAuthenticationError* error;
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    XCTAssertEqual(revision + 1, [mStore getCurrenRevision]);
    XCTAssertTrue((revision + 1) >= [mStore getArchivedRevision]);
}

-(BOOL) syncRemoveItem: (ADTokenCacheStoreItem*) item
{
    ADAuthenticationError* error;
    int64_t revision = [mStore getCurrenRevision];
    XCTAssertTrue(revision >= [mStore getArchivedRevision]);
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    BOOL present = (nil != [mStore getItemWithKey:key userId:item.userInformation.userId]);
    [mStore removeItem:item error:&error];
    ADAssertNoError;
    if (present)
    {
        //Something was removed:
        XCTAssertEqual(revision + 1, [mStore getCurrenRevision]);
        XCTAssertTrue((revision + 1) >= [mStore getArchivedRevision]);
    }
    else
    {
        //Nothing removed:
        XCTAssertEqual(revision, [mStore getCurrenRevision]);
        XCTAssertTrue(revision >= [mStore getArchivedRevision]);
    }
    return present;
}

//Esnures that two keys are the same:
-(void) verifySameWithKey: (ADTokenCacheStoreKey*) key1
                     key2: (ADTokenCacheStoreKey*) key2
{
    XCTAssertNotNil(key1);
    XCTAssertNotNil(key2);
    ADAssertStringEquals(key1.authority, key2.authority);
    ADAssertStringEquals(key1.resource, key2.resource);
    ADAssertStringEquals(key1.clientId, key2.clientId);
    XCTAssertTrue([key1 isEqual:key2]);
}

//Creates a copy of item changing only the user:
-(ADTokenCacheStoreItem*) copyItem: (ADTokenCacheStoreItem*) item
                                  withNewUser: (NSString*) newUser
{
    ADTokenCacheStoreItem* newItem = [item copy];
    XCTAssertNotNil(newItem);
    XCTAssertNotEqualObjects(newItem, item, "Not copied.");
    [self verifySameWithItem:item item2:newItem];
    XCTAssertNotEqualObjects(item.userInformation, newItem.userInformation, "Not a deep copy");
    if (newUser)
    {
        ADAuthenticationError* error;
        newItem.userInformation = [ADUserInformation userInformationWithUserId:newUser error:&error];
        ADAssertNoError;
    }
    else
    {
        newItem.userInformation = nil;
    }
    
    return newItem;
}

//Verifies consistency and copying between what was passed to the cache,
//what is stored and what is returned:
- (void)verifyCopyingWithItem: (ADTokenCacheStoreItem*) original
                     internal: (ADTokenCacheStoreItem*) internal
                     returned: (ADTokenCacheStoreItem*) returned
{
    XCTAssertNotEqualObjects(original, internal, "The object was not copied.");
    [self verifySameWithItem:original item2:internal];
    XCTAssertNotEqualObjects(internal, returned, "The internal storage was not copied.");
    [self verifySameWithItem:internal item2:returned];
    XCTAssertNotEqualObjects(original, returned, "The returned value was not copied.");
}

//Verifies that the items in the cache are copied, so that the developer
//cannot accidentally modify them. The method tests the geters too.
-(void) testCopySingleObject
{
    XCTAssertTrue(mCache.count == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item = [self createCacheItem];
    ADAuthenticationError* error;
    [self syncAddOrUpdateItem:item];
    XCTAssertTrue(mCache.count == 1);
    
    //getItemWithKey:userId
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    NSDictionary* dictionary = [mCache objectForKey:key];
    XCTAssertTrue(dictionary.count == 1);
    ADTokenCacheStoreItem* internalItem = [dictionary objectForKey:item.userInformation.userId.trimmedString.lowercaseString];
    ADTokenCacheStoreItem* returnedItem = [mStore getItemWithKey:key userId:item.userInformation.userId];
    [self verifyCopyingWithItem:item internal:internalItem returned:returnedItem];
    
    //getItemsWithKey:userId and nil userId:
    ADTokenCacheStoreItem* returnedItemForNil = [mStore getItemWithKey:key userId:nil];
    [self verifyCopyingWithItem:item internal:internalItem returned:returnedItemForNil];
    
    //getItemsWithKey:
    NSArray* items = [mStore getItemsWithKey:key];
    XCTAssertTrue(items.count == 1);
    ADTokenCacheStoreItem* returnedFromArray = [items objectAtIndex:0];
    XCTAssertNotNil(returnedFromArray);
    [self verifyCopyingWithItem:item internal:internalItem returned:returnedFromArray];
    
    //allItems:
    NSArray* allItems = [mStore allItems];
    XCTAssertTrue(items.count == 1);
    ADTokenCacheStoreItem* returnedFromAll = [allItems objectAtIndex:0];
    XCTAssertNotNil(returnedFromArray);
    [self verifyCopyingWithItem:item internal:internalItem returned:returnedFromAll];
}

- (void)verifyTwoItems: (ADTokenCacheStoreItem*) item1
                 item2: (ADTokenCacheStoreItem*) item2
             internal1: (ADTokenCacheStoreItem*) internal1
             internal2: (ADTokenCacheStoreItem*) internal2
                 array: (NSArray*) array
{
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 2);
    for(ADTokenCacheStoreItem* i in array)
    {
        XCTAssertNotEqualObjects(i, item1);
        XCTAssertNotEqualObjects(i, item2);
        XCTAssertNotEqualObjects(i, internal1);
        XCTAssertNotEqualObjects(i, internal2);
        if ([i.userInformation.userId isEqualToString:item1.userInformation.userId])
        {
            [self verifyCopyingWithItem:item1 internal:internal1 returned:i];
        }
        else
        {
            [self verifyCopyingWithItem:item2 internal:internal2 returned:i];
        }
    }
}

//Adds more than one object for a given key and verifies that extraction copies correctly
//Tests al of the getters:
-(void) testCopyMultipleObjects
{
    XCTAssertTrue(mCache.count == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item1 = [self createCacheItem];
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    [self syncAddOrUpdateItem:item1];
    XCTAssertTrue(mCache.count == 1);
    
    ADTokenCacheStoreItem* item2 = [self copyItem:item1 withNewUser:@"  another user  "];
    //We will use the otherKey later to ensure that the getters work with any proper key object.
    ADTokenCacheStoreKey* otherKey = [item2 extractKeyWithError:&error];
    [self verifySameWithKey:key key2:otherKey];
    ADAssertNoError;
    [self syncAddOrUpdateItem:item2];
    ADAssertNoError;
    XCTAssertTrue(mCache.count == 1);//They use the same key

    //Find the internal stored items:
    ADTokenCacheStoreItem* internal1;
    ADTokenCacheStoreItem* internal2;
    NSDictionary* inner = [[mCache allValues] objectAtIndex:0];
    XCTAssertTrue(inner.count == 2);
    for(ADTokenCacheStoreItem* i in [inner allValues])
    {
        if ([i.userInformation.userId isEqualToString:item1.userInformation.userId])
        {
            internal1 = i;
        }
        else if ([i.userInformation.userId isEqualToString:item2.userInformation.userId])
        {
            internal2 = i;
        }
    }
    XCTAssertNotNil(internal1, "Item1 not stored");
    XCTAssertNotNil(internal2, "Item2 not stored");
    
    //All values:
    NSArray* allValues = [mStore allItems];
    [self verifyTwoItems:item1 item2:item2 internal1:internal1 internal2:internal2 array:allValues];
    
    //getItemsWithKey
    NSArray* allWithKey = [mStore getItemsWithKey:otherKey];
    [self verifyTwoItems:item1 item2:item2 internal1:internal1 internal2:internal2 array:allWithKey];
    
    //Individual items with the userId:
    ADTokenCacheStoreItem* item1Return = [mStore getItemWithKey:key userId:item1.userInformation.userId];
    [self verifyCopyingWithItem:item1 internal:internal1 returned:item1Return];
    ADTokenCacheStoreItem* item2Return = [mStore getItemWithKey:otherKey userId:item2.userInformation.userId];
    [self verifyCopyingWithItem:item2 internal:internal2 returned:item2Return];
    
    //get item with id of nil:
    ADTokenCacheStoreItem* itemReturn = [mStore getItemWithKey:otherKey userId:nil];
    if ([itemReturn.userInformation.userId isEqualToString:item1.userInformation.userId])
    {
        [self verifyCopyingWithItem:item1 internal:internal1 returned:itemReturn];
    }
    else
    {
        [self verifyCopyingWithItem:item2 internal:internal2 returned:itemReturn];
    }
}

-(void) testComplex
{
    XCTAssertTrue(mCache.count == 0);
    ADTokenCacheStoreItem* item1 = [self createCacheItem];
    ADAuthenticationError* error;
    
    //one item:
    [self syncAddOrUpdateItem:item1];
    XCTAssertTrue(mCache.count == 1);
    NSDictionary* dict1 = [[mCache allValues] objectAtIndex:0];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    
    //add the same item and ensure that the counts do not change:
    [self syncAddOrUpdateItem:item1];
    XCTAssertTrue(mCache.count == 1);
    dict1 = [[mCache allValues] objectAtIndex:0];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    
    //Add an item with different key:
    ADTokenCacheStoreItem* item2 = [self createCacheItem];
    item2.resource = @"another authority";
    [self syncAddOrUpdateItem:item2];
    XCTAssertTrue(mCache.count == 2);
    dict1 = [[mCache allValues] objectAtIndex:0];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    dict1 = [[mCache allValues] objectAtIndex:1];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    
    //add an item with the same key, but some other change:
    ADTokenCacheStoreItem* item3 = [self createCacheItem];
    item3.accessToken = @"another token";
    [self syncAddOrUpdateItem:item3];
    XCTAssertTrue(mCache.count == 2);
    dict1 = [[mCache allValues] objectAtIndex:0];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    dict1 = [[mCache allValues] objectAtIndex:1];
    XCTAssertNotNil(dict1);
    XCTAssertTrue(dict1.count == 1);
    
    //Add an item with the same key, but different user:
    ADTokenCacheStoreItem* item4 = [self copyItem:item1 withNewUser:@"   another user   "];
    [self syncAddOrUpdateItem:item4];
    XCTAssertTrue(mCache.count == 2);
    XCTAssertTrue(mStore.allItems.count == 3);
    
    //Add an item with nil user:
    ADTokenCacheStoreItem* item5 = [self copyItem:item1 withNewUser:nil];
    [self syncAddOrUpdateItem:item5];
    XCTAssertTrue(mCache.count == 2);
    XCTAssertTrue(mStore.allItems.count == 4);
    
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    
    //Now few getters:
    ADTokenCacheStoreItem* itemReturn5 = [mStore getItemWithKey:key userId:nil];
    [self verifySameWithItem:item5 item2:itemReturn5];
    NSArray* array = [mStore getItemsWithKey:key];
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 3);
    
    //Now test the removers:
    BOOL removed = [self syncRemoveItem:item1];
    XCTAssertTrue(removed);
    XCTAssertTrue(mCache.count == 2);
    array = mStore.allItems;
    XCTAssertTrue(array.count == 3);
    
    //This will remove two elements, as the userId is not specified:
    [mStore removeItemWithKey:key userId:nil];
    XCTAssertTrue(mStore.allItems.count  == 1);
    XCTAssertTrue(mCache.count == 1);
    
    [mStore removeAll];
    array = mStore.allItems;
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 0);
    XCTAssertTrue(mCache.count == 0);
}

-(void) threadProc
{
    @autoreleasepool//Autorelease pool for the whole thread. Required.
    {
        //Create as much date as possible outside of the run loop to cause the most
        //thread contentions in the loop:
        ADTokenCacheStoreItem* item1 = [self createCacheItem];
        ADAuthenticationError* error;
        item1.userInformation = [ADUserInformation userInformationWithUserId:@"foo" error:nil];
        ADAssertNoError;
        ADTokenCacheStoreItem* item2 = [self createCacheItem];
        item2.userInformation = [ADUserInformation userInformationWithUserId:@"bar" error:nil];
        ADAssertNoError;
        ADTokenCacheStoreItem* item3 = [self createCacheItem];
        item3.userInformation = nil;
        ADTokenCacheStoreKey* key123 = [item3 extractKeyWithError:&error];
        ADAssertNoError;

        ADTokenCacheStoreItem* item4 = [self createCacheItem];
        item4.authority = @"https://www.authority.com/tenant.com";
        ADTokenCacheStoreKey* key4 = [item3 extractKeyWithError:&error];
        ADAssertNoError;
        
        NSDate* end = [NSDate dateWithTimeIntervalSinceNow:sThreadsRunTime];//few seconds into the future
        NSDate* now;
        do
        {
            @autoreleasepool//The cycle will create constantly objects, so it needs its own autorelease pool
            {
                [mStore removeAll];
                [mStore addOrUpdateItem:item1 error:&error];
                ADAssertNoError;
                [mStore addOrUpdateItem:item2 error:&error];
                ADAssertNoError;
                [mStore addOrUpdateItem:item3 error:&error];
                ADAssertNoError;
                [mStore addOrUpdateItem:item4 error:&error];
                ADAssertNoError;
                //We are intentionally not testing all getters here, as the goal
                //is to have as many writes as reads in the dictionary for higher chance of thread collisions
                //Implementing
                //all possible get combinations will skew the test towards reads:
                NSArray* array = [mStore getItemsWithKey:key123];
                XCTAssertNotNil(array);
                array = [mStore allItems];
                array = [mStore getItemsWithKey:key4];
                [mStore getItemWithKey:key123 userId:nil];
                [mStore getItemWithKey:key123 userId:item1.userInformation.userId];
                [mStore getItemWithKey:key123 userId:@"not real"];
                [mStore getItemWithKey:key4 userId:nil];
                [mStore getItemWithKey:key4 userId:@"not real"];
                
                [mStore removeItemWithKey:key123 userId:item1.userInformation.userId];
                [mStore removeItemWithKey:key123 userId:item2.userInformation.userId];
                [mStore removeItemWithKey:key123 userId:nil];
                [mStore removeItemWithKey:key4 userId:nil];
                
                now = [NSDate dateWithTimeIntervalSinceNow:0];
            }//Inner authorelease pool
        }
        while ([end compare:now] == NSOrderedDescending);
        if (OSAtomicIncrement32(&sThreadsFinished) == sMaxThreads)
        {
            //The last one finished, signal completion:
            dispatch_semaphore_signal(sThreadsSemaphore);
        }
    }//@autorealease pool. End of the method
}

-(void) testMultipleThreads
{
    //The signal to denote completion:
    sThreadsSemaphore = dispatch_semaphore_create(0);
    sThreadsFinished = 0;
    XCTAssertTrue(sThreadsSemaphore, "Failed to create a semaphore");

    for(int i = 0; i < sMaxThreads; ++i)
    {
        [self performSelectorInBackground:@selector(threadProc) withObject:self];
    }
    if (dispatch_semaphore_wait(sThreadsSemaphore, dispatch_time(DISPATCH_TIME_NOW, (sThreadsRunTime + 5)*NSEC_PER_SEC)))
    {
        XCTFail("Timeout. Most likely one or more of the threads have crashed or hanged.");
    }
    else
    {
        [self waitForPersistenceWithLine:__LINE__];//Ensure clean exit.
    }
}

//Waits for persistence
-(void) waitForPersistenceWithLine:(int)line
{
    NSDate* start = [NSDate dateWithTimeIntervalSinceNow:0];

    NSTimeInterval elapsed = 0;
    while (elapsed < sPersistenceTimeout && [mStore getArchivedRevision] < [mStore getCurrenRevision])
    {
        usleep(1000);//In microseconds, so sleep 1 milisecond at a time.
        elapsed = -[start timeIntervalSinceNow];//The method returns negative value
    }
    
    NSLog(@"Waiting for persistence to catch up took: %f", elapsed);
    if ([mStore getArchivedRevision] < [mStore getCurrenRevision])
    {
        [self recordFailureWithDescription:@"Timeout while waiting for the persistence to catch up." inFile:@"" __FILE__ atLine:line expected:NO];
    }
    if ([mStore getArchivedRevision] > [mStore getCurrenRevision])
    {
        [self recordFailureWithDescription:@"Misaligned archived and current revisions." inFile:@"" __FILE__ atLine:line expected:NO];
    }
}

//Waits and checks that the cache was persisted.
//The logs should be cleared before performing the operation that leads to persistence.
-(void) validateAsynchronousPersistenceWithLine: (int) line
{
    [self waitForPersistenceWithLine:__LINE__];
    [self assertLogsContain:sPersisted
                    logPart:TEST_LOG_INFO
                       file:__FILE__
                       line:line];
}

//Ensures that the cache is eventually persisted when modified:
-(void) testAsynchronousPersistence
{
    //Start clean:
    [self waitForPersistenceWithLine:__LINE__];
    [self clearLogs];

    //Add an item:
    ADTokenCacheStoreItem* item = [self createCacheItem];
    ADAuthenticationError* error;
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    [self validateAsynchronousPersistenceWithLine:__LINE__];
    
    //Remove an item:
    error = nil;
    [self clearLogs];
    [mStore removeItem:item error:&error];
    ADAssertNoError;
    [self validateAsynchronousPersistenceWithLine:__LINE__];
    
    error = nil;
    [self clearLogs];
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    [self validateAsynchronousPersistenceWithLine:__LINE__];
    
    error = nil;
    [self clearLogs];
    [mStore removeAll];
    [self validateAsynchronousPersistenceWithLine:__LINE__];
}

//Add large number of items to the cache and makes. Acts as a mini-stress test too
//Checks that the persistence catches up and that the number of persistence operations is
//disproportionately smaller than the cache updates:
-(void) testBulkPersistence
{
    long numItems = 500;//Keychain is relatively slow
    ADTokenCacheStoreItem* original = [self createCacheItem];
    NSMutableArray* allItems = [NSMutableArray new];
    for (long i = 0; i < numItems; ++i)
    {
        NSString* user = [NSString stringWithFormat:@"User: %ld", i];
        ADTokenCacheStoreItem* item = [self copyItem:original withNewUser:user];
        [allItems addObject:item];
    }

    [self waitForPersistenceWithLine:__LINE__];//Just in case.
    [self clearLogs];
    ADAuthenticationError* error;

    for(ADTokenCacheStoreItem* item in allItems)
    {
        [mStore addOrUpdateItem:item error:&error];
    }
    ADAssertNoError;//The error accumulates.
    [self waitForPersistenceWithLine:__LINE__];
    //Now count persistence tasks and ensure that they are << numItems:
    int numPersisted = [self adCountOfLogOccurrencesIn:TEST_LOG_INFO ofString:sPersisted];
    int numAttempted = [self adCountOfLogOccurrencesIn:TEST_LOG_MESSAGE ofString:sNoNeedForPersistence];
    
    XCTAssertTrue(numPersisted > 0);
    XCTAssertTrue(numPersisted < numItems/10, "Too many persistence requests, the bulk processing does not work.");
    //The simulator is able to dequeue very fast, so effectively, the atempted requests will be
    //relatively high there. The test importance is to ensure that we are not attempting as much as we update:
    XCTAssertTrue(numAttempted < numItems/2, "Too many attempts to persist, the checking if persistence is queued does not work.");
    
    //Restore:
    [mStore removeAll];
    [self waitForPersistenceWithLine:__LINE__];
}


//Plays with the persistence conditions:
-(void) testEnsureArchived
{
    [self waitForPersistenceWithLine:__LINE__];
    
    ADAuthenticationError* error;
    [self clearLogs];
    
    //All up to date, attempt persistance:
    XCTAssertTrue([mStore ensureArchived:&error]);
    ADAssertNoError;
    ADAssertLogsContainValue(TEST_LOG_MESSAGE, sNoNeedForPersistence);
    
    //Fake modification and ensure storing:
    [self clearLogs];
    [mStore setCurrentRevision:5];
    [mStore setArchivedRevision:([mStore getCurrenRevision] - 2)];
    XCTAssertTrue([mStore ensureArchived:&error]);
    ADAssertNoError;
    XCTAssertTrue([mStore getArchivedRevision] == [mStore getCurrenRevision]);
    ADAssertLogsContainValue(TEST_LOG_INFO, sPersisted);
    ADAssertLogsContainValue(TEST_LOG_INFO, mStore.cacheLocation);
    
    //Ensure no storing, as the persistence caught up:
    [self clearLogs];
    XCTAssertTrue([mStore ensureArchived:&error]);
    ADAssertNoError;
    ADAssertLogsContainValue(TEST_LOG_MESSAGE, sNoNeedForPersistence);
    ADAssertLogsDoNotContainValue(TEST_LOG_INFO, sPersisted);
}

-(void) verifyCacheContainsItem: (ADTokenCacheStoreItem*) item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    
    ADTokenCacheStoreItem* read = [mStore getItemWithKey:key userId:item.userInformation.userId];
    [self verifySameWithItem:item item2:read];
}

-(void) testInitializer
{
    XCTAssertNil([[ADPersistentTokenCacheStore alloc] initWithLocation:nil]);
    XCTAssertNil([[ADPersistentTokenCacheStore alloc] initWithLocation:@"   "]);
    
    //Abstract methods
    NSString* location = @"location";
    ADPersistentTokenCacheStore* instance = [[ADPersistentTokenCacheStore alloc] initWithLocation:location];
    ADAssertStringEquals(instance.cacheLocation, location);
    XCTAssertThrows([instance addInitialCacheItems], "This method should call non-implmented unpersistence.");
}

//Tests the persistence:
-(void) testaddInitialElements
{
    ADAuthenticationError* error;

    //Start clean, add, remove items to ensure serialization of empty array:
    ADTokenCacheStoreItem* original = [self createCacheItem];
    [mStore addOrUpdateItem:original error:&error];
    ADAssertNoError;
    [mStore removeAll];
    [self waitForPersistenceWithLine:__LINE__];
    BOOL result = [mStore addInitialCacheItems];
    XCTAssertFalse(result, "There shouldn't be any elements.");
    XCTAssertTrue(mCache.count == 0);
    
    //Add some items, read them back:
    //These two share the same key:
    ADTokenCacheStoreItem* authority1one = [self copyItem:original withNewUser:@"1"];
    ADTokenCacheStoreItem* authority1two = [self copyItem:original withNewUser:@"2"];
    
    //Different key:
    ADTokenCacheStoreItem* authority2 = [self copyItem:original withNewUser:@"1"];
    authority2.authority = @"https://www.anotherauthority.com/tenant.com";
    ADTokenCacheStoreItem* clientId2 = [self copyItem:original withNewUser:@"1"];
    clientId2.clientId = @"clientId2";

    //Add the items:
    [mStore addOrUpdateItem:authority1one error:&error];
    [mStore addOrUpdateItem:authority1two error:&error];
    [mStore addOrUpdateItem:authority2 error:&error];
    [mStore addOrUpdateItem:clientId2 error:&error];
    ADAssertNoError;
    [self waitForPersistenceWithLine:__LINE__];
    XCTAssertTrue(mStore.allItems.count == 4);

    
    //Stop serialization clear the cache and read it from the file,
    //make sure that the file has the same values:
    [mStore setArchivedRevision:LONG_LONG_MAX];//Temporarily disable serialization
    [mStore removeAll];
    XCTAssertTrue(mCache.count == 0);
    result = [mStore addInitialCacheItems];//Load manually
    XCTAssertTrue(result);
    XCTAssertTrue(mStore.allItems.count == 4);
    [self verifyCacheContainsItem:authority1one];
    [self verifyCacheContainsItem:authority1two];
    [self verifyCacheContainsItem:authority2];
    [self verifyCacheContainsItem:clientId2];
    [mStore setArchivedRevision:[mStore getCurrenRevision]];//Restore the serialization
    
    //Clean up:
    [mStore removeAll];
    ADAssertNoError;
    [self waitForPersistenceWithLine:__LINE__];
}

@end
