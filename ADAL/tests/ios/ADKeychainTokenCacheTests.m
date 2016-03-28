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
#import "XCTestCase+TestHelperMethods.h"
#import <libkern/OSAtomic.h>
#import "ADAuthenticationSettings.h"
#import "ADAuthenticationContext.h"
#import "ADKeychainTokenCache.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"
#import "ADTokenCacheKey.h"

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
    [mStore testRemoveAll:nil];//Attempt to clear all things from the keychain
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
    [mStore addOrUpdateItem:item correlationId:nil error:nil];
    
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
    XCTAssertTrue([mStore addOrUpdateItem:item1 correlationId:nil error:&error], @"addOrUpdate failed: %@ (%ld)", error.errorDetails, (long)error.code);
    XCTAssertNil(error);
    
    // Add the same item again for fun
    XCTAssertTrue([mStore addOrUpdateItem:item1 correlationId:nil error:&error], @"addOrUpdate failed: %@ (%ld)", error.errorDetails, (long)error.code);
    XCTAssertNil(error);
    
    // Verify there's only a single item in the allItems list
    NSArray* items = [mStore allItems:&error];
    XCTAssertNotNil(items);
    XCTAssertNil(error);
    XCTAssertEqual(items.count, 1);
    
    ADTokenCacheItem* returnedItem = [mStore getItemWithKey:[self adCreateCacheKey] userId:@"eric@contoso.com" correlationId:nil error:&error];
    XCTAssertNotNil(returnedItem);
    XCTAssertNil(error, @"getItemWithKey failed: %@ (%ld)", error.errorDetails, (long)error.code);
    
    XCTAssertEqualObjects(item1, returnedItem);
}

- (void)testAddTwoItemsWithSameKey
{
    ADAuthenticationError* error = nil;
    ADTokenCacheItem* item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    //one item:
    XCTAssertTrue([mStore addOrUpdateItem:item1 correlationId:nil error:&error]);
    XCTAssertNil(error);
    
    // Now create an item with the same authority + resource + client id but a
    // different user
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    XCTAssertTrue([mStore addOrUpdateItem:item2 correlationId:nil error:&error]);
    XCTAssertNil(error);
    
    // Now try to get an item with that same key, because there are two items with the
    // same user id we should see a multiple users error
    ADTokenCacheItem* returnedItem = [mStore getItemWithKey:[self adCreateCacheKey] userId:nil correlationId:nil error:&error];
    XCTAssertNil(returnedItem);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_CACHE_MULTIPLE_USERS);
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
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 3);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item1 from cache
    ADTokenCacheKey* key1 = [item1 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId correlationId:nil error:&error];
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
    retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId correlationId:nil error:&error];
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
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 1);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item1 from cache
    ADTokenCacheKey* key1 = [item1 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem1 = [mStore getItemWithKey:key1 userId:item1.userInformation.userId correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item1, retrievedItem1);
    
    
    //add item2 with refresh token
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    ADAssertNoError;
    XCTAssertEqual([self count], 2);
    XCTAssertEqual([self tombstoneCount], 0);
    
    //getItemWithKey should be able to retrieve item2 from cache
    ADTokenCacheKey* key2 = [item2 extractKey:&error];
    ADAssertNoError;
    ADTokenCacheItem* retrievedItem2 = [mStore getItemWithKey:key2 userId:item2.userInformation.userId correlationId:nil error:&error];
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
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"stan@contoso.com"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADTokenCacheItem* item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [item4 setClientId:@"a different client id"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
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
    [mStore addOrUpdateItem:item1 correlationId:nil error:&error];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item2 setResource:@"resource 2"];
    [mStore addOrUpdateItem:item2 correlationId:nil error:&error];
    //add another two more items
    ADTokenCacheItem* item3 = [self adCreateCacheItem:@"jack@contoso.com"];
    [mStore addOrUpdateItem:item3 correlationId:nil error:&error];
    ADTokenCacheItem* item4 = [self adCreateCacheItem:@"rose@contoso.com"];
    [mStore addOrUpdateItem:item4 correlationId:nil error:&error];
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

- (void)testHardcodedData
{
    // A serialized token cache item in base 64 form
    NSString* base64String = @"YnBsaXN0MDDUAQIDBAUGh4hYJHZlcnNpb25YJG9iamVjdHNZJGFyY2hpdmVyVCR0b3ASAAGGoK8QLAcIGxwdHh8gISUrNTk+P2FiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3+DVSRudWxs2QkKCwwNDg8QERITFBUWFxgZGlYkY2xhc3NZYXV0aG9yaXR5WHJlc291cmNlXxAPdXNlckluZm9ybWF0aW9uWWV4cGlyZXNPblhjbGllbnRJZFxyZWZyZXNoVG9rZW5bYWNjZXNzVG9rZW5fEA9hY2Nlc3NUb2tlblR5cGWAK4ADgAKACoAIgASAB4AFgAZaPHJlc291cmNlPl8QKGh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS9jb21tb25fECQyN0FEODNDOS1GQzA1LTRBNkMtQUYwMS0zNkVEQTQyRUQxOEZePGFjY2VzcyB0b2tlbj5WQmVhcmVyXxAPPHJlZnJlc2ggdG9rZW4+0iIJIyRXTlMudGltZSNBLoSAAAAAAIAJ0iYnKClaJGNsYXNzbmFtZVgkY2xhc3Nlc1ZOU0RhdGWiKCpYTlNPYmplY3TVLC0uLwkwMTIzNF8QEXVzZXJJZERpc3BsYXlhYmxlWWFsbENsYWltc1pyYXdJZFRva2VuVnVzZXJJZAmADoANgAuAKtIJNjc4WU5TLnN0cmluZ4AMXxAWbXlmYWtldXNlckBjb250b3NvLmNvbdImJzo7XxAPTlNNdXRhYmxlU3RyaW5nozw9Kl8QD05TTXV0YWJsZVN0cmluZ1hOU1N0cmluZ18RAlBleUowZVhBaU9pSktWMVFpTENKaGRXUWlPaUpqTTJNM1pqVmxOUzAzTVRVekxUUTBaRFF0T1RCbE5pMHpNamsyT0Raa05EaGtOellpTENKcGMzTWlPaUpvZEhSd2N6b3ZMM04wY3k1M2FXNWtiM2R6TG01bGRDODJabVF4WmpWalpDMWhPVFJqTFRRek16VXRPRGc1WWkwMll6VTVPR1UyWkRnd05EZ3ZJaXdpYVdGMElqb3hNemczTWpJME1UWTVMQ0p1WW1ZaU9qRXpPRGN5TWpReE5qa3NJbVY0Y0NJNk1UTTROekl5TnpjMk9Td2lkbVZ5SWpvaU1TNHdJaXdpZEdsa0lqb2lObVprTVdZMVkyUXRZVGswWXkwME16TTFMVGc0T1dJdE5tTTFPVGhsTm1RNE1EUTRJaXdpYjJsa0lqb2lOVE5qTm1GalpqSXRNamMwTWkwME5UTTRMVGt4T0dRdFpUYzRNalUzWldNNE5URTJJaXdpZFhCdUlqb2liWGxtWVd0bGRYTmxja0JqYjI1MGIzTnZMbU52YlNJc0luVnVhWEYxWlY5dVlXMWxJam9pYlhsbVlXdGxkWE5sY2tCamIyNTBiM052TG1OdmJTSXNJbk4xWWlJNklqQkVlRzVCYkV4cE1USkpka2RNWDJSSE0yUkVUV3N6ZW5BMlFWRklibXBuYjJkNWFXMDFRVmR3VTJNaUxDSm1ZVzFwYkhsZmJtRnRaU0k2SWxWelpYSWlMQ0puYVhabGJsOXVZVzFsSWpvaVJtRnJaU0o500BBCUJRYFdOUy5rZXlzWk5TLm9iamVjdHOuQ0RFRkdISUpLTE1OT1CAD4AQgBGAEoATgBSAFYAWgBeAGIAZgBqAG4AcrlJTVFVWV1hZU1tcXVJfgB2AHoAfgCCAIYAigCOAJIAegCWAJoAngB2AKIApU3VwblNuYmZTZXhwU2lzc1NvaWRTdHlwU3ZlclNhdWRTaWF0W2ZhbWlseV9uYW1lU3N1YlN0aWRbdW5pcXVlX25hbWVaZ2l2ZW5fbmFtZV8QFm15ZmFrZXVzZXJAY29udG9zby5jb20SUq9caRJSr2p5XxA9aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4L18QJDUzYzZhY2YyLTI3NDItNDUzOC05MThkLWU3ODI1N2VjODUxNlNKV1RTMS4wXxAkYzNjN2Y1ZTUtNzE1My00NGQ0LTkwZTYtMzI5Njg2ZDQ4ZDc2VFVzZXJfECswRHhuQWxMaTEySXZHTF9kRzNkRE1rM3pwNkFRSG5qZ29neWltNUFXcFNjXxAkNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4VEZha2XSJid8fVxOU0RpY3Rpb25hcnmifipcTlNEaWN0aW9uYXJ50iYngIFfEBFBRFVzZXJJbmZvcm1hdGlvbqKCKl8QEUFEVXNlckluZm9ybWF0aW9u0iYnhIVfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW2ihipfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW1fEA9OU0tleWVkQXJjaGl2ZXLRiYpUcm9vdIABAAgAEQAaACMALQAyADcAZgBsAH8AhgCQAJkAqwC1AL4AywDXAOkA6wDtAO8A8QDzAPUA9wD5APsBBgExAVgBZwFuAYABhQGNAZYBmAGdAagBsQG4AbsBxAHPAeMB7QH4Af8CAAICAgQCBgIIAg0CFwIZAjICNwJJAk0CXwJoBLwEwwTLBNYE5QTnBOkE6wTtBO8E8QTzBPUE9wT5BPsE/QT/BQEFEAUSBRQFFgUYBRoFHAUeBSAFIgUkBSYFKAUqBSwFLgUyBTYFOgU+BUIFRgVKBU4FUgVeBWIFZgVyBX0FlgWbBaAF4AYHBgsGDwY2BjsGaQaQBpUGmganBqoGtwa8BtAG0wbnBuwHBAcHBx8HMQc0BzkAAAAAAAACAQAAAAAAAACLAAAAAAAAAAAAAAAAAAAHOw==";
    
    
    NSData* itemData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    XCTAssertNotNil(itemData);
    
    NSString* service = [NSString stringWithFormat:@"MSOpenTech.ADAL.1|%@|%@|%@",
                         [@"https://login.microsoftonline.com/common" adBase64UrlEncode],
                         [@"<resource>" adBase64UrlEncode],
                         // The underlying keychain code lowercases the client ID before saving it out to keychain
                         [@"27ad83c9-fc05-4a6c-af01-36eda42ed18f" adBase64UrlEncode]];
    
    NSDictionary* query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecAttrAccount : [@"myfakeuser@contoso.com" adBase64UrlEncode],
                             (id)kSecAttrService : service,
                             (id)kSecAttrGeneric : [@"MSOpenTech.ADAL.1" dataUsingEncoding:NSUTF8StringEncoding],
                             (id)kSecValueData : itemData,
                             };
    
    OSStatus status = SecItemAdd((CFDictionaryRef)query, NULL);
    XCTAssertEqual(status, errSecSuccess);
    
    ADKeychainTokenCache* cache = [[ADKeychainTokenCache alloc] initWithGroup:nil];
    ADAuthenticationError* error = nil;
    
    ADTokenCacheKey* key = [ADTokenCacheKey keyWithAuthority:@"https://login.microsoftonline.com/common"
                                                    resource:@"<resource>"
                            // Client ID is upper cased here to make sure it does the proper case conversion
                                                    clientId:@"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F"
                                                       error:&error];
    XCTAssertNotNil(key);
    
    ADTokenCacheItem* item = [cache getItemWithKey:key userId:@"myfakeuser@contoso.com" correlationId:nil error:&error];
    XCTAssertNotNil(item);
    
    XCTAssertEqualObjects(item.accessToken, @"<access token>");
    XCTAssertEqualObjects(item.refreshToken, @"<refresh token>");
    XCTAssertEqualObjects(item.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(item.userInformation.userId, @"myfakeuser@contoso.com");
    
    NSDictionary* deleteQuery = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                                   (id)kSecAttrAccount : [@"myfakeuser@contoso.com" adBase64UrlEncode],
                                   (id)kSecAttrService : service,
                                   (id)kSecAttrGeneric : [@"MSOpenTech.ADAL.1" dataUsingEncoding:NSUTF8StringEncoding],
                                   };
    
    status = SecItemDelete((CFDictionaryRef)deleteQuery);
    XCTAssertEqual(status, errSecSuccess);
}

@end
