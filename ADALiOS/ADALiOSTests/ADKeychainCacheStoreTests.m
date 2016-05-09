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
#import "ADTestUtils.h"
#import <libkern/OSAtomic.h>
#import "../ADALiOS/public/ADAuthenticationSettings.h"
#import "../ADALiOS/public/ADAuthenticationContext.h"
#import "../ADALiOS/ADKeychainTokenCacheStore.h"

dispatch_semaphore_t sThreadsSemaphore;//Will be signalled when the last thread is done. Should be initialized and cleared in the test.
volatile int32_t sThreadsFinished;//The number of threads that are done. Should be set to 0 at the beginning of the test.
const int sMaxThreads = 10;//The number of threads to spawn
int sThreadsRunTime = 5;//How long the bacground threads would run

//Some logging constant to help with testing the persistence:
NSString* const sPersisted = @"successfully persisted";
NSString* const sNoNeedForPersistence = @"No need for cache persistence.";
NSString* const sFileNameEmpty = @"Invalid or empty file name";

@interface ADDefaultTokenCacheStoreTests : XCTestCase
{
    ADKeychainTokenCacheStore* mStore;
}
@end

@implementation ADDefaultTokenCacheStoreTests

- (void)setUp
{
    [super setUp];
    
    mStore = [[ADKeychainTokenCacheStore alloc] init];
    [mStore setServiceKey:@"MSOpenTech.ADAL.test"];
    
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    [mStore removeAll:nil];//Start clean before each test
}

- (void)tearDown
{
    [mStore removeAll:nil];//Attempt to clear the junk from the keychain
    mStore = nil;
    
    [super tearDown];
}

#define VERIFY_CACHE_COUNT(_count) { \
    ADAuthenticationError* err = nil; \
    NSArray* _ALL = [mStore allItems:&err]; \
    XCTAssertNil(err); \
    XCTAssertEqual(_ALL.count, _count); \
}

//A wrapper around addOrUpdateItem, checks automatically for errors.
//Works on single threaded environment only, as it checks the counts:
#define ADD_OR_UPDATE_ITEM(_item, _expectAdd) \
{\
    ADAuthenticationError* error = nil; \
    NSUInteger _COUNT = [mStore allItems:nil].count; \
    [mStore addOrUpdateItem:_item error:&error]; \
    ADAssertNoError; \
    VERIFY_CACHE_COUNT(_expectAdd ? _COUNT + 1 : _COUNT); \
    ADTokenCacheStoreKey* key = [_item extractKeyWithError:&error]; \
    ADAssertNoError; \
    ADTokenCacheStoreItem* _read = [mStore getItemWithKey:key error:&error]; \
    ADAssertNoError; \
    XCTAssertEqualObjects(_item, _read); \
}

//Esnures that two keys are the same:
#define VERIFY_SAME_WITH_KEY(_key1, _key2) \
{\
    XCTAssertNotNil(_key1);\
    XCTAssertNotNil(_key2);\
    XCTAssertEqualObjects(_key1.authority, _key2.authority);\
    XCTAssertEqualObjects(_key1.resource, _key2.resource);\
    XCTAssertEqualObjects(_key1.clientId, _key2.clientId);\
    XCTAssertTrue([_key1 isEqual:_key2]);\
}

//Creates a copy of item changing only the user:
#define COPY_ITEM_WITH_NEW_USER(_newItem, _item, _newUser) \
{ \
    _newItem = [_item copy]; \
    XCTAssertNotNil(_newItem); \
    XCTAssertEqualObjects(_item, _newItem); \
    if (_newUser) \
    { \
        ADAuthenticationError* error; \
        _newItem.profileInfo = [ADProfileInfo profileInfoWithUserId:_newUser error:&error]; \
        ADAssertNoError; \
    } \
    else \
    { \
        _newItem.profileInfo = nil; \
    } \
} \

//Verifies that the items in the cache are copied, so that the developer
//cannot accidentally modify them. The method tests the getters too.
- (void)testCopySingleObject
{
    VERIFY_CACHE_COUNT(0);
    
    NSString* errorDetails = nil;
    ADTokenCacheStoreItem* item = [[ADTestUtils defaultUtils] createCacheItem:&errorDetails];
    XCTAssertNotNil(item, @"Failed to create item: %@", errorDetails);
    
    ADAuthenticationError* error = nil;
    [mStore addOrUpdateItem:item
                      error:&error];
    ADAssertNoError;
    VERIFY_CACHE_COUNT(1);

    //getItemWithKey:userId
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    ADTokenCacheStoreItem* exact = [mStore getItemWithKey:key error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item, exact);
    
    //allItems:
    NSArray* allItems = [mStore allItems:&error];
    ADAssertNoError;
    ADTokenCacheStoreItem* returnedFromAll = [allItems objectAtIndex:0];
    XCTAssertNotNil(returnedFromAll);
    XCTAssertEqualObjects(item, returnedFromAll);
}

- (void)testComplex
{
    ADAuthenticationError* error = nil;
    VERIFY_CACHE_COUNT(0);
    
    ADTestUtils* utils = [[ADTestUtils alloc] init];
    
    NSString* errorDetails = nil;
    ADTokenCacheStoreItem* item1 = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(item1, @"Failed to create item: %@", errorDetails);
    
    //one item:
    ADD_OR_UPDATE_ITEM(item1, YES);
    
    //add the same item and ensure that the counts do not change:
    ADD_OR_UPDATE_ITEM(item1, NO);
    
    //add an item with the same key, but some other change:
    [utils setAccessToken:@"another token"];
    ADTokenCacheStoreItem* item3 = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(item3, @"Failed to create item: %@", errorDetails);
    ADD_OR_UPDATE_ITEM(item3, NO);

    //Add an item with the same key, but different user:
    [utils setUsername:@"another user"];
    ADTokenCacheStoreItem* item4 = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(item4, @"Failed to create item: %@", errorDetails);
    ADD_OR_UPDATE_ITEM(item4, YES);
    
    //Add an item with nil user:
//    ADTokenCacheStoreItem* item5 = nil;
//    COPY_ITEM_WITH_NEW_USER(item5, item1, nil);
//    ADD_OR_UPDATE_ITEM(item5, YES);
//    
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    
    VERIFY_CACHE_COUNT(2);
    
    //Now test the removers:
    [mStore removeItemWithKey:key error:&error];//Specific user
    ADAssertNoError;
    VERIFY_CACHE_COUNT(1);
    
    [mStore removeAll:&error];
    ADAssertNoError;
    VERIFY_CACHE_COUNT(0);
}

- (void)testScopeEscalationAndIntersection
{
    VERIFY_CACHE_COUNT(0);
    
    NSString* errorDetails = nil;
    ADTokenCacheStoreItem* item = [[ADTestUtils defaultUtils] createCacheItem:&errorDetails];
    XCTAssertNotNil(item, @"Failed to create item: %@", errorDetails);
    item.scopes = [NSSet setWithObjects:@"scope1", nil];
    ADD_OR_UPDATE_ITEM(item, YES);
    
    item.scopes = [NSSet setWithObjects:@"scope2", nil];
    ADD_OR_UPDATE_ITEM(item, YES);
    
    item.scopes = [NSSet setWithObjects:@"scope3", nil];
    ADD_OR_UPDATE_ITEM(item, YES);
    
    // This item should replace 2 of the items in cache...
    item.scopes = [NSSet setWithObjects:@"scope1", @"scope3", nil];
    ADAuthenticationError* error = nil;
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    ADTokenCacheStoreItem* read = [mStore getItemWithKey:[item extractKeyWithError:nil] error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item, read);
    VERIFY_CACHE_COUNT(2);
    
    item.scopes = [NSSet setWithObjects:@"scope4", @"scope5", nil];
    ADD_OR_UPDATE_ITEM(item, YES);
    VERIFY_CACHE_COUNT(3);
    
    // This one should intersect with all of the items in cache replacing them all
    item.scopes = [NSSet setWithObjects:@"scope1", @"scope2", @"scope5", nil];
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    read = [mStore getItemWithKey:[item extractKeyWithError:nil] error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item, read);
    VERIFY_CACHE_COUNT(1);
}

//Add large number of items to the cache. Acts as a mini-stress test too
//Checks that the persistence catches up and that the number of persistence operations is
//disproportionately smaller than the cache updates:
- (void)testBulkPersistence
{
    long numItems = 500;//Keychain is relatively slow
    NSString* errorDetails = nil;
    ADTestUtils* utils = [[ADTestUtils alloc] init];
    ADTokenCacheStoreItem* original = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(original, @"Failed to create item: %@", errorDetails);
    NSMutableArray* allItems = [NSMutableArray new];
    for (long i = 0; i < numItems; ++i)
    {
        NSString* user = [NSString stringWithFormat:@"User: %ld", i];
        [utils setUsername:user];
        ADTokenCacheStoreItem* item = [utils createCacheItem:&errorDetails];
        XCTAssertNotNil(item, @"Failed to create item: %@", errorDetails);
        [allItems addObject:item];
    }

    ADAuthenticationError* error = nil;
    for(ADTokenCacheStoreItem* item in allItems)
    {
        [mStore addOrUpdateItem:item error:&error];
        ADAssertNoError;
    }

    //Restore:
    [mStore removeAll:&error];
    ADAssertNoError;
}

- (void)testInitializer
{
    ADKeychainTokenCacheStore* simple = [ADKeychainTokenCacheStore new];
    XCTAssertNotNil(simple);
    XCTAssertNotNil(simple.sharedGroup);
    NSString* group = @"test";
    ADKeychainTokenCacheStore* withGroup = [[ADKeychainTokenCacheStore alloc] initWithGroup:group];
    XCTAssertNotNil(withGroup);
}

//- (void)testsharedKeychainGroupProperty
//{
//    //Put an item in the cache:
//    ADAssertLongEquals(0, [self count]);
//    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
//    ADAuthenticationError* error = nil;
//    [mStore addOrUpdateItem:item error:&error];
//    ADAssertNoError;
//    ADAssertLongEquals(1, [self count]);
//    
//    //Test the property:
//    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
//    ADKeychainTokenCacheStore* keychainStore = (ADKeychainTokenCacheStore*)mStore;
//    XCTAssertNotNil(settings.sharedCacheKeychainGroup);
//    XCTAssertNotNil(keychainStore.sharedGroup);
//    NSString* groupName = @"com.microsoft.ADAL";
//    settings.sharedCacheKeychainGroup = groupName;
//    XCTAssertEqualObjects(settings.sharedCacheKeychainGroup, groupName);
//    
//    //Restore back to default
//    keychainStore.sharedGroup = nil;
//    XCTAssertNil(keychainStore.sharedGroup);
//    [mStore removeAll:&error];
//    ADAssertNoError;
//    ADAssertLongEquals(0, [self count]);
//}

- (void)testMultiplePolicies
{
    // RTs should be keyed off of the policy, ATs off both scope and policy.
    
    ADTestUtils* utils = [ADTestUtils new];
    NSString* errorDetails = nil;
    ADAuthenticationError* error = nil;
    ADTokenCacheStoreItem* item = nil;
    
    // Start by verifying that cache is empty
    NSArray* allItems = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertEqual([allItems count], 0, @"Expected the cache to be empty, cache contents: %@", allItems);
    
    // Create an item in cache with no policy
    [utils setRefreshToken:@"nopolicy"];
    ADTokenCacheStoreItem* noPolicyItem = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(noPolicyItem, @"Failed to create no policy cache item: %@", errorDetails);
    [mStore addOrUpdateItem:noPolicyItem error:&error];
    ADAssertNoError;
    
    // Verify we can pull it out of cache
    ADTokenCacheStoreKey* noPolicyKey = [utils createKey];
    item = [mStore getItemWithKey:noPolicyKey error:nil];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item, noPolicyItem);
    
    // Add another item with a policy
    [utils setRefreshToken:@"policy1"];
    [utils setPolicy:@"policy1"];
    ADTokenCacheStoreItem* policy1Item = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(policy1Item, @"Failed to create policy 1 cache item: %@", errorDetails);
    [mStore addOrUpdateItem:policy1Item error:&error];
    ADAssertNoError;
    
    // Verify that it's there too
    ADTokenCacheStoreKey* policy1Key = [utils createKey];
    item = [mStore getItemWithKey:policy1Key error:nil];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item, policy1Item);
    
    // And that the previous item is still there
    item = [mStore getItemWithKey:noPolicyKey error:nil];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item, noPolicyItem);
    
    // Update the first item
    [utils setPolicy:nil];
    [utils setRefreshToken:@"updatedRefreshToken"];
    noPolicyItem = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(noPolicyItem, @"Failed to create no policy cache item: %@", errorDetails);
    [mStore addOrUpdateItem:noPolicyItem error:&error];
    ADAssertNoError;
    
    // Verify it's updated
    item = [mStore getItemWithKey:noPolicyKey error:nil];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item, noPolicyItem);
    
    // Verify that the second item was not modified
    item = [mStore getItemWithKey:policy1Key error:nil];
    XCTAssertNotNil(item);
    XCTAssertEqualObjects(item, policy1Item);
}

@end
