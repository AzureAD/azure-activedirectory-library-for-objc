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
#import "ADCacheTombstoneWrapper.h"

@interface ADCacheTombstoneWrapperTest : XCTestCase
{
    ADCacheTombstoneWrapper* mStore;
    ADKeychainTokenCache* keychainCacheBeingWrapped;
}
@end

@implementation ADCacheTombstoneWrapperTest

- (void)setUp
{
    [super setUp];
    keychainCacheBeingWrapped = [[ADKeychainTokenCache alloc] init];
    [keychainCacheBeingWrapped testRemoveAll:nil]; //Start clean before each test
    mStore = [[ADCacheTombstoneWrapper alloc] initWithCache:keychainCacheBeingWrapped];
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    XCTAssertTrue([mStore isKindOfClass:[ADCacheTombstoneWrapper class]]);
}

- (void)tearDown
{
    [keychainCacheBeingWrapped testRemoveAll:nil];//Attempt to clear the junk from the keychain
    mStore = nil;
    
    [self adTestEnd];
    [super tearDown];
}

/*! Count of items in cache store (not including tombstones). */
- (long)count
{
    ADAuthenticationError* error;
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
    NSArray* all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    int itemCount = 0;
    for (ADTokenCacheItem * item in all)
    {
        if ([item tombstone])
        {
            itemCount++;
        }
    }
    return itemCount;
}

-(void) testItemDelete
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    ADAuthenticationError* error = nil;
    
    //add item1
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
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
    
    
    //add item2
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
    //Since we didn't set tombstone property to YES, it should be deleted from cache.
    [mStore removeItem:item1 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //remove item2.
    //Since we didn't set tombstone property to YES, it should be deleted from cache.
    [mStore removeItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 0);
    
    
}

-(void) testItemTombstone
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
    
    //tombstone item1
    [self setCacheItemAsTombstone:item1];
    [mStore removeItem:item1 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    XCTAssertEqual([self tombstoneCount], 1);
    //verify that item1 is updated
    [self verifyCacheContainsItem:item1];
    
    //getItemWithKey is NOT able to retrieve item1 from cache because it is a tombstone,
    //although item1 can still be retrieved using [mStore allItems]
    ADTokenCacheKey* key1 = [item1 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId error:&error];
    ADAssertNoError;
    XCTAssertNil(retrievedItem1);
    
    //tombstone item2
    [self setCacheItemAsTombstone:item2];
    [mStore removeItem:item2 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 2);
    //verify that item2 is updated
    [self verifyCacheContainsItem:item2];
    
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
    [self setCacheItemAsTombstone:item3];
    [mStore removeItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 3);
    //verify that item3 is updated
    [self verifyCacheContainsItem:item3];
    
    //tombstone an item when cache is empty (except tombstones)
    [mStore removeItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 0);
    XCTAssertEqual([self tombstoneCount], 3);
    
    //update a tombstone to be a normal item
    [item3 setTombstone:NO];
    [mStore addOrUpdateItem:item3 error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 2);
    //verify that item3 is updated
    [self verifyCacheContainsItem:item3];
    
}

-(void)setCacheItemAsTombstone:(ADTokenCacheItem*)item
{
    if (item)
    {
        [item setTombstone:YES];
        [item setCorrelationId:[[NSUUID UUID] UUIDString]];
        [item setBundleId:[[NSBundle mainBundle] bundleIdentifier]];
        [item setRefreshToken:@"<tombstone>"];
    }
}

-(void) verifyCacheContainsItem: (ADTokenCacheItem*) item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    
    //Find the one (if any) that has userId equal to nil:
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

@end
