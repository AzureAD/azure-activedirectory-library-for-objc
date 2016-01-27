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

- (long)count
{
    ADAuthenticationError* error;
    NSArray* all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    return all.count;
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
    XCTAssertTrue([mStore addOrUpdateItem:item1 error:&error], @"addOrUpdate failed: %@ (%d)", error.errorDetails, error.code);
    XCTAssertNil(error);
    
    // Add the same item again for fun
    XCTAssertTrue([mStore addOrUpdateItem:item1 error:&error], @"addOrUpdate failed: %@ (%d)", error.errorDetails, error.code);
    XCTAssertNil(error);
    
    // Verify there's only a single item in the allItems list
    NSArray* items = [mStore allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    
    ADTokenCacheItem* returnedItem = [mStore getItemWithKey:[self adCreateCacheKey] userId:@"eric@contoso.com" error:&error];
    XCTAssertNotNil(returnedItem);
    XCTAssertNil(error, @"getItemWithKey failed: %@ (%d)", error.errorDetails, error.code);
    
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

@end
