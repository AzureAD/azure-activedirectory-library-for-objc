//
//  ADTokenCacheStorageWrapperTests.m
//  ADALiOS
//
//  Created by Ryan Pangrle on 1/12/16.
//  Copyright © 2016 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ADCacheStorage.h"
#import "ADTokenCacheStorageWrapper.h"
#import "ADTokenCacheStoreItem.h"
#import "ADTokenCacheStoreKey.h"
#import "NSString+ADHelperMethods.h"
#import "ADUserInformation.h"

@interface ADTestSimpleStorage : NSObject <ADCacheStorageDelegate>
{
@public
    BOOL _changed;
    BOOL _retrieveStorageCalled;
    BOOL _retrieveIfUpdatedCalled;
    
    NSData* _cache;
}

- (void)changeCache:(NSData*)cache;
- (void)resetFlags;

@end

@implementation ADTestSimpleStorage

/*!
 Called on initial storage retrieval
 */
- (NSData*)retrieveStorage
{
    _changed = NO;
    _retrieveStorageCalled = YES;
    return _cache;
}

/*!
 Called when checking if the cache needs to be updated, return nil if nothing has changed since the last storage operation.
 Can be the same implementation as -retrieveStorage, however performance will suffer.
 */
- (NSData*)retrieveIfUpdated
{
    _retrieveIfUpdatedCalled = YES;
    if (_changed)
    {
        _changed = NO;
        return _cache;
    }
    
    return nil;
}

/*!
 Called by ADAL to update the cache storage
 */
- (void)saveToStorage:(NSData*)data
{
    _cache = data;
    _changed = NO;
}

- (void)changeCache:(NSData *)cache
{
    _cache = cache;
    _changed = YES;
}

- (void)resetFlags
{
    _retrieveIfUpdatedCalled = NO;
    _retrieveStorageCalled = NO;
}

@end

@interface ADTokenCacheStorageWrapperTests : XCTestCase

@end

@implementation ADTokenCacheStorageWrapperTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}


// This test creates two different storage wrappers. Adds an item into the first, and then copies the backing
// store to the second wrapper and make sure the item gets through.
- (void)testAddItemAllItems
{
    ADAuthenticationError* error = nil;
    ADTestSimpleStorage* storage1 = [[ADTestSimpleStorage alloc] init];
    ADTokenCacheStorageWrapper* wrapper1 = [[ADTokenCacheStorageWrapper alloc] initWithStorage:storage1];
    
    ADTestSimpleStorage* storage2 = [[ADTestSimpleStorage alloc] init];
    ADTokenCacheStorageWrapper* wrapper2 = [[ADTokenCacheStorageWrapper alloc] initWithStorage:storage2];
    
    
    // Make sure we've loaded up the storage but haven't checked for updates
    XCTAssertTrue(storage1->_retrieveStorageCalled);
    XCTAssertFalse(storage1->_retrieveIfUpdatedCalled);
    
    
    // Make sure both wrappers start off showing empty and that they checked for updates
    XCTAssertNil([wrapper1 allItems:&error]);
    XCTAssertNil(error);
    XCTAssertTrue(storage1->_retrieveIfUpdatedCalled);
    XCTAssertNil(storage1->_cache);
    [storage1 resetFlags];
    
    XCTAssertNil([wrapper2 allItems:&error]);
    XCTAssertNil(error);
    XCTAssertTrue(storage2->_retrieveIfUpdatedCalled);
    XCTAssertNil(storage2->_cache);
    [storage2 resetFlags];
    
    NSDictionary* part1_claims = @{ @"aud" : @"c3c7f5e5-7153-44d4-90e6-329686d48d76",
                                    @"iss" : @"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                    @"iat" : @"1387224169",
                                    @"nbf" : @"1387224169",
                                    @"exp" : @"1387227769" };
    
    NSDictionary* idtoken_claims = @{ @"ver" : @"1.0",
                                      @"tid" : @"6fd1f5cd-a94c-4335-889b-6c598e6d8048",
                                      @"oid" : @"53c6acf2-2742-4538-918d-e78257ec8516",
                                      @"upn" : @"regina@contoso.com",
                                      @"unique_name" : @"regina@contoso.com",
                                      @"sub" : @"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc",
                                      @"family_name" : @"George",
                                      @"given_name" : @"Regina"
                                      };
    
    NSString* idtoken = [NSString stringWithFormat:@"%@.%@",
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:part1_claims options:0 error:nil]],
                         [NSString Base64EncodeData:[NSJSONSerialization dataWithJSONObject:idtoken_claims options:0 error:nil]]];
    
    // Add an item into wrapper 1
    ADTokenCacheStoreItem* item1 = [[ADTokenCacheStoreItem alloc] init];
    item1.userInformation = [ADUserInformation userInformationWithIdToken:idtoken error:nil];
    item1.authority = @"https://login.windows.net/contoso.com";
    item1.accessToken = @"ThisIsMyAcessToken";
    item1.refreshToken = @"ThisIsMyRefreshToken";
    item1.accessTokenType = @"Bearer";
    item1.resource = @"Fetch";
    [wrapper1 addOrUpdateItem:item1 error:&error];
    XCTAssertTrue(storage1->_retrieveIfUpdatedCalled);
    XCTAssertNotNil(storage1->_cache);
    
    NSArray* items = nil;
    
    // Make sure the item shows up in allItems
    items = [wrapper1 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    XCTAssertEqualObjects(items[0], item1);
    
    // Make sure the pointers are *not* equal (we want to make sure it's a copy,
    // a reference, just in case something in the item changes)
    XCTAssertEqual(items[0], item1);
    [storage1 resetFlags];

    // Copy the data from storage 1 into storage 2 "under the covers"
    [storage2 changeCache:storage1->_cache];
    
    // Call allItems and make sure it picks up on the cache change and shows us the item
    items = [wrapper2 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    XCTAssertEqualObjects(items[0], item1);
    
    // Add a second item into the storage with the information as the first and make sure it shows up in all items.
    ADTokenCacheStoreItem* item2 = [item1 copy];
    
    // We're modifying item1 to make sure that it doesn't show up in the allItems array
    item1.resource = @"Stop";
    [wrapper1 addOrUpdateItem:item1 error:&error];
    XCTAssertNil(error);

    items = [wrapper1 allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 2);
    
    // Make sure both of the items are in the array
    XCTAssertTrue([items[0] isEqual:item1] || [items[1] isEqual:item1], @"Item1 wasn't found in allItems!");
    XCTAssertTrue([items[0] isEqual:item2] || [items[1] isEqual:item2], @"Item2 wasn't found in allItems!");
}


@end
