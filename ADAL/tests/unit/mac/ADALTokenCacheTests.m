// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import <XCTest/XCTest.h>
#import "ADALTokenCache.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADALTokenCache+Internal.h"
#import "ADALTokenCacheItem.h"
#import "ADALUserInformation.h"

@interface ADALTokenCacheTests : ADTestCase
{
    ADALTokenCache *mStore;
}
@end

@implementation ADALTokenCacheTests

- (void)setUp

{
    [super setUp];
    
    mStore = [ADALTokenCache new];
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    XCTAssertTrue([mStore isKindOfClass:[ADALTokenCache class]]);
}

- (void)tearDown
{
    mStore = nil;
    
    [super tearDown];
}

- (void)testRemoveAllForClientId_whenClientIdNil_shouldReturnNo
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add three items with the same client ID and one with a different client ID
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"a different client id"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove all items with nil client ID
    NSString *clientId = nil;
    XCTAssertFalse([mStore removeAllForClientId:clientId error:&error]);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    XCTAssertEqual([self count], 4);
}

- (void)testRemoveAllForClientId_whenClientIdNotNil_shouldRemoveTokens
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add three items with the same client ID and one with a different client ID
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"a different client id"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove all items with client ID as TEST_CLIENT_ID
    [mStore removeAllForClientId:TEST_CLIENT_ID error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    //only item4 is left in cache
    [self verifyCacheContainsItem:item4];
}

- (void)testRemoveAllForUserIdAndClientId_whenUserIdNil_shouldReturnNo
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same client ID and same user ID but differnet resource
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setResource:@"resource 1"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setResource:@"resource 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove items with nil user ID
    NSString *userId = nil;
    XCTAssertFalse([mStore removeAllForUserId:userId clientId:TEST_CLIENT_ID error:&error]);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    XCTAssertEqual([self count], 4);
}

- (void)testRemoveAllForUserIdAndClientId_whenClientIdNil_shouldReturnNo
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same client ID and same user ID but differnet resource
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setResource:@"resource 1"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setResource:@"resource 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove items with nil client ID
    NSString *clientId = nil;
    XCTAssertFalse([mStore removeAllForUserId:@"eric@contoso.com" clientId:clientId error:&error]);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    XCTAssertEqual([self count], 4);
}

- (void)testRemoveAllForUserIdAndClientId_whenBothUserIdClientIdNotNil_shouldRemoveTokens
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same client ID and same user ID but differnet resource
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setResource:@"resource 1"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setResource:@"resource 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove items with user ID as @"eric@contoso.com" and client ID as TEST_CLIENT_ID
    [mStore removeAllForUserId:@"eric@contoso.com" clientId:TEST_CLIENT_ID error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    
    //only item3 and item4 are left in cache
    [self verifyCacheContainsItem:item3];
    [self verifyCacheContainsItem:item4];
}

- (void)testWipeAllItemsForUserId_whenUserIdNil_shouldReturnNo
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same user ID but differnet client ID
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setClientId:@"client 1"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setClientId:@"client 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items with different user ID but with same client ID as above
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [item3 setClientId:@"client 1"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"client 2"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove items with nil user ID
    NSString *userId = nil;
    XCTAssertFalse([mStore wipeAllItemsForUserId:userId error:&error]);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    XCTAssertEqual([self count], 4);
}

- (void)testWipeAllItemsForUserId_whenUserIdNotNil_shouldDeleteAllItems
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADALAuthenticationError *error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    
    //add two items with the same user ID but differnet client ID
    ADALTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setClientId:@"client 1"];
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADALTokenCacheItem *item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setClientId:@"client 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items with different user ID but with same client ID as above
    ADALTokenCacheItem *item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [item3 setClientId:@"client 1"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADALTokenCacheItem *item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"client 2"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
    
    ADAssertNoError;
    XCTAssertEqual([self count], 4);
    
    //remove items with user ID as @"eric@contoso.com" and client ID as TEST_CLIENT_ID
    XCTAssertTrue([mStore wipeAllItemsForUserId:@"eric@contoso.com" error:&error]);
    
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    
    [self verifyCacheContainsItem:item3];
    [self verifyCacheContainsItem:item4];
}

/*! Count of items in cache store. */
- (long)count
{
    ADALAuthenticationError *error = nil;
    NSArray *all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    
    return all.count;
}

- (void)verifyCacheContainsItem: (ADALTokenCacheItem*) item
{
    XCTAssertNotNil(item);
    ADALAuthenticationError *error;
    
    NSArray *all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    
    ADALTokenCacheItem *read = nil;
    for(ADALTokenCacheItem *i in all)
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

- (void)testADALTokenCacheGetItemWithKey_whenTombstonesInCacheAndNoOtherItemsInCache_shouldNotReturnTombstones
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    ADALTokenCacheItem *item = [wrapper getItemWithKey:[testItem extractKey:nil] userId:testItem.userInformation.userId correlationId:nil error:&error];
    XCTAssertNil(item);
    XCTAssertNil(error);
}

- (void)testADALTokenCacheGetItemWithKey_whenTombstonesInCacheAndOtherItemsInCache_shouldNotReturnTombstones_AndReturnCorrectItem
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    ADALTokenCacheItem *secondItem = [self adCreateCacheItem:@"eric2@contoso.com"];
    result = [wrapper addOrUpdateItem:secondItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    ADALTokenCacheItem *item = [wrapper getItemWithKey:[secondItem extractKey:nil] userId:nil correlationId:nil error:&error];
    XCTAssertNotNil(item);
    XCTAssertNil(error);
    XCTAssertEqualObjects(item, secondItem);
}

- (void)testADALTokenCacheGetItemsWithKey_whenTombstonesInCacheAndNoOtherItemsInCache_shouldNotReturnTombstones
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    NSArray *items = [wrapper getItemsWithKey:[testItem extractKey:nil] userId:testItem.userInformation.userId correlationId:nil error:&error];
    XCTAssertEqual([items count], 0);
    XCTAssertNil(error);
}

- (void)testADALTokenCacheGetItemsWithKey_whenTombstonesInCacheAndOtherItemsInCache_shouldNotReturnTombstones_AndReturnCorrectItem
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    ADALTokenCacheItem *secondItem = [self adCreateCacheItem:@"eric2@contoso.com"];
    result = [wrapper addOrUpdateItem:secondItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    NSArray *items = [wrapper getItemsWithKey:[secondItem extractKey:nil] userId:nil correlationId:nil error:&error];
    XCTAssertEqual([items count], 1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(items[0], secondItem);
}


- (void)testADALTokenCacheGetAllItems_whenTomsbtonesInCache_shouldNotReturnTombstones
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    ADALTokenCacheItem *secondItem = [self adCreateCacheItem:@"eric2@contoso.com"];
    result = [wrapper addOrUpdateItem:secondItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    NSArray *items = [wrapper allItems:&error];
    XCTAssertEqual([items count], 1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(items[0], secondItem);
}

- (void)testADALTokenCacheSetItem_whenTombstoneInCache_shouldReplaceTombstoneWithNewItem
{
    ADALTokenCache *wrapper = [[ADALTokenCache alloc] init];

    ADALAuthenticationError *error = nil;
    ADALTokenCacheItem *testItem = [self adCreateCacheItem:@"eric@contoso.com"];
    testItem.refreshToken = @"<tombstone>";
    BOOL result = [wrapper addOrUpdateItem:testItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    // Save item with the same resource
    ADALTokenCacheItem *secondItem = [self adCreateCacheItem:@"eric@contoso.com"];
    result = [wrapper addOrUpdateItem:secondItem correlationId:nil error:&error];
    XCTAssertTrue(result);
    XCTAssertNil(error);

    NSArray *items = [wrapper allItems:&error];
    XCTAssertEqual([items count], 1);
    XCTAssertNil(error);
    XCTAssertEqualObjects(items[0], secondItem);
}

@end
