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
#import <libkern/OSAtomic.h>
#import "ADAuthenticationSettings.h"
#import "ADAuthenticationContext.h"
#import "ADKeychainTokenCache.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
dispatch_semaphore_t sThreadsSemaphore;//Will be signalled when the last thread is done. Should be initialized and cleared in the test.
volatile int32_t sThreadsFinished;//The number of threads that are done. Should be set to 0 at the beginning of the test.
const int sMaxThreads = 3;//The number of threads to spawn
int sThreadsRunTime = 5;//How long the bacground threads would run

//Some logging constant to help with testing the persistence:
NSString* const sPersisted = @"successfully persisted";
NSString* const sNoNeedForPersistence = @"No need for cache persistence.";
NSString* const sFileNameEmpty = @"Invalid or empty file name";

@interface ADKeychainTokenCacheTests : XCTestCase
{
    ADKeychainTokenCache* mStore;
}
@end

@implementation ADKeychainTokenCacheTests

- (void)setUp
{
    [super setUp];
    
    mStore = [[ADKeychainTokenCache alloc] init];
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    XCTAssertTrue([mStore isKindOfClass:[ADKeychainTokenCache class]]);
    [mStore testRemoveAll:nil];//Start clean before each test
}

- (void)tearDown
{
    [mStore testRemoveAll:nil];//Attempt to clear the junk from the keychain
    mStore = nil;
    
    [self adTestEnd];
    [super tearDown];
}

/*! Count of items in cache store (not including tombstones). */
- (long)count
{
    ADAuthenticationError* error = nil;
    NSArray* all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    int itemCount = 0;
    for (ADTokenCacheItem * item in all)
    {
        if (![item tombstone])
        {
            itemCount++;
        }
    }
    return itemCount;
}

/*! Count of tombstones in cache store. */
- (long)tombstoneCount
{
    ADAuthenticationError* error;
    NSArray* tombstones = [mStore allTombstones:&error];
    ADAssertNoError;
    XCTAssertNotNil(tombstones);
    
    return [tombstones count];
}

//Verifies that the items in the cache are copied, so that the developer
//cannot accidentally modify them. The method tests the getters too.
- (void)testCopySingleObject
{
    [mStore testRemoveAll:nil];
    
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric_cartman@contoso.com"];
    [mStore addOrUpdateItem:item error:nil];
    
    NSArray* allItems = [mStore allItems:nil];
    
    XCTAssertEqual([allItems count], 1);
    XCTAssertEqualObjects(item, allItems[0]);
}

// Add the same item the cache twice and verify that it's not duplicated in the cache
- (void)testAddTwice
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    
    //one item:
    XCTAssertTrue([mStore addOrUpdateItem:item1 error:&error], @"addOrUpdate failed: %@ (%ld)", error.errorDetails, (long)error.code);
    XCTAssertNil(error);
    
    // Add the same item again for fun
    XCTAssertTrue([mStore addOrUpdateItem:item1 error:&error], @"addOrUpdate failed: %@ (%ld)", error.errorDetails, (long)error.code);
    XCTAssertNil(error);
    
    // Verify there's only a single item in the allItems list
    NSArray* items = [mStore allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    
    ADTokenCacheItem* returnedItem = [mStore getItemWithKey:[self adCreateCacheKey] userId:@"eric@contoso.com" error:&error];
    XCTAssertNotNil(returnedItem);
    XCTAssertNil(error, @"getItemWithKey failed: %@ (%ld)", error.errorDetails, (long)error.code);
    
    XCTAssertEqualObjects(item1, returnedItem);
}

- (void)testAddTwoItemsWithSameKey
{
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    //one item:
    XCTAssertTrue([mStore addOrUpdateItem:item1 error:&error]);
    XCTAssertNil(error);
    
    // Now create an item with the same authority + resource + client id but a
    // different user
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    XCTAssertTrue([mStore addOrUpdateItem:item2 error:&error]);
    XCTAssertNil(error);
    
    // Now try to get an item with that same key, because there are two items with the
    // same user id we should see a multiple users error
    ADTokenCacheItem* returnedItem = [mStore getItemWithKey:[self adCreateCacheKey] userId:nil error:&error];
    XCTAssertNil(returnedItem);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_MULTIPLE_USERS);
}

- (void)testInitializer
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADKeychainTokenCache* simple = [ADKeychainTokenCache new];
    XCTAssertNotNil(simple);
    XCTAssertNotNil(simple.sharedGroup);
    NSString* group = @"test";
    ADKeychainTokenCache* withGroup = [[ADKeychainTokenCache alloc] initWithGroup:group];
    XCTAssertNotNil(withGroup);
}

//test [ADKeychainTokenCache removeItem:error:]
//for the case where item contains refresh token and will be set as a tombstone.
- (void)testItemTombstone
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add three items:
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [mStore addOrUpdateItem:item1 error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 error:&error];
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 3);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item1 from cache
    ADTokenCacheKey* key1 = [item1 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item1, retrievedItem1);
    
    //tombstone item1
    [mStore removeItem:item1 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    XCTAssertEqual([self tombstoneCount], 1);
    //verify that item1 is updated
    [self verifyCacheContainsTombstone:item1];
    
    //getItemWithKey is NOT able to retrieve item1 from cache because it is a tombstone,
    //although item1 can still be retrieved using [mStore allItems]
    key1 = [item1 extractKey:&error];
    ADAssertNoError;
    retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId error:&error];
    ADAssertNoError;
    XCTAssertNil(retrievedItem1);
    
    //tombstone item2
    [mStore removeItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 2);
    //verify that item2 is updated
    [self verifyCacheContainsTombstone:item2];
    
    //tombstone an item which has already been tombstoned
    [mStore removeItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 2);
    
    //tombstone a non-exist item. Should have no change to cache
    ADTokenCacheItem* random = [self adCreateCacheItem:@"nonexist@contoso.com"];
    [mStore removeItem:random error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 2);
    
    //tombstone item3
    [mStore removeItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 3);
    //verify that item3 is updated
    [self verifyCacheContainsTombstone:item3];
    
    //tombstone an item when cache is empty (except tombstones)
    [mStore removeItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 3);
}

//test [ADKeychainTokenCache removeItem:error:]
//for the case where item does not contain refresh token and will be deleted.
- (void)testItemDelete
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    ADAuthenticationError* error = nil;
    
    //add item1 with no refresh token
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setRefreshToken:nil];
    [mStore addOrUpdateItem:item1 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item1 from cache
    ADTokenCacheKey* key1 = [item1 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item1, retrievedItem1);
    
    
    //add item2 with refresh token
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item2 from cache
    ADTokenCacheKey* key2 = [item2 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem2 = [mStore getItemWithKey:key2 userId:item2.userInformation.userId error:&error];
    XCTAssertEqualObjects(item2, retrievedItem2);
    
    //remove item1.
    //Since item1 does not contain refresh token, it should be deleted from cache.
    [mStore removeItem:item1 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //remove item2.
    //Since item2 contains refresh token, it should become a tombstone.
    [mStore removeItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 1);
}

- (void)testRemoveAllForClientId
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add three items with the same client ID and one with a different client ID
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [mStore addOrUpdateItem:item1 error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 error:&error];
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 error:&error];
    ADTokenCacheItem* item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"a different client id"];
    [mStore addOrUpdateItem:item4 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //remove all items with client ID as TEST_CLIENT_ID
    [mStore removeAllForClientId:TEST_CLIENT_ID error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 3);
    //only item4 is left in cache while the others should be tombstones
    [self verifyCacheContainsItem:item4];
}

- (void)testRemoveAllForUserId
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same client ID and same user ID but differnet resource
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setResource:@"resource 1"];
    [mStore addOrUpdateItem:item1 error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setResource:@"resource 2"];
    [mStore addOrUpdateItem:item2 error:&error];
    //add another two more items
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 error:&error];
    ADTokenCacheItem* item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [mStore addOrUpdateItem:item4 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //remove items with user ID as @"eric@contoso.com" and client ID as TEST_CLIENT_ID
    [mStore removeAllForUserId:@"eric@contoso.com" clientId:TEST_CLIENT_ID error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    XCTAssertEqual([self tombstoneCount], 2);
    //only item3 and item4 are left in cache while the other twi should be tombstones
    [self verifyCacheContainsItem:item3];
    [self verifyCacheContainsItem:item4];
}

- (void)verifyCacheContainsItem: (ADTokenCacheItem*) item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    
    NSArray* all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    
    ADTokenCacheItem* read = nil;
    for(ADTokenCacheItem* i in all)
    {
        XCTAssertNotNil(i);
        if ([i.userInformation.userId isEqualToString:item.userInformation.userId]
            && [i.authority isEqualToString:item.authority]
            && [i.resource isEqualToString:item.resource]
            && [i.clientId isEqualToString:item.clientId])
        {
            read = i;
            break;;
        }
    }
    XCTAssertEqualObjects(read, item);
}

- (void)verifyCacheContainsTombstone:(ADTokenCacheItem *)item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    
    NSArray* all = [mStore allTombstones:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    
    ADTokenCacheItem* read = nil;
    for(ADTokenCacheItem* i in all)
    {
        XCTAssertNotNil(i);
        if ([i.userInformation.userId isEqualToString:item.userInformation.userId]
            && [i.authority isEqualToString:item.authority]
            && [i.resource isEqualToString:item.resource]
            && [i.clientId isEqualToString:item.clientId])
        {
            read = i;
            break;;
        }
    }
    XCTAssertEqualObjects(read, item);
}

- (void)testGarbageInKeychain
{
    ADKeychainTokenCache* cache = [ADKeychainTokenCache new];
    
    // Grab the default keychain query dict to make sure that we're
    // adding the garbage data in just the right place that we might
    // trip up the keychain code.
    NSDictionary* defaultQuery = [cache defaultKeychainQuery];
    NSMutableDictionary* addQuery = [NSMutableDictionary dictionaryWithDictionary:defaultQuery];
    
    void* bytes = malloc(1024);
    NSData* garbageData = [NSData dataWithBytes:bytes length:1024];
    [addQuery setObject:@"I'm a service!" forKey:(id)kSecAttrService];
    [addQuery setObject:TEST_USER_ID forKey:(id)kSecAttrAccount];
    [addQuery setObject:garbageData forKey:(id)kSecValueData];
    
    // Add garbage into the keychain for the keychain cache code
    // to trip on
    OSStatus status = SecItemAdd((CFDictionaryRef)addQuery, NULL);
    XCTAssertEqual(status, errSecSuccess);
    
    ADAuthenticationError* error = nil;
    NSArray* allItems = [cache allItems:&error];
    XCTAssertNotNil(allItems);
    XCTAssertNil(error, @"allItems failed with error: %@", error.errorDetails);
    
    NSMutableDictionary* deleteQuery = [NSMutableDictionary dictionaryWithDictionary:defaultQuery];
    [deleteQuery setObject:@"I'm a service!" forKey:(id)kSecAttrService];
    [deleteQuery setObject:TEST_USER_ID forKey:(id)kSecAttrAccount];
    
    SecItemDelete((CFDictionaryRef)deleteQuery);
}

@end
