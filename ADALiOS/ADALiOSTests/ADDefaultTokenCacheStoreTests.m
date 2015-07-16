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
#import "../ADALiOS/ADAuthenticationSettings.h"
#import "../ADALiOS/ADAuthenticationContext.h"
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
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
    
    mStore = [[ADKeychainTokenCacheStore alloc] init];
    [mStore setServiceKey:@"MSOpenTech.ADAL.test"];
    
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    [mStore removeAll:nil];//Start clean before each test
}

- (void)tearDown
{
    [mStore removeAll:nil];//Attempt to clear the junk from the keychain
    mStore = nil;
    
    [self adTestEnd];
    [super tearDown];
}

-(long) count
{
    ADAuthenticationError* error;
    NSArray* all = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(all);
    return all.count;
}


-(void) testKeychainAttributesWithKeyNonAsciiUserId
{
    SEL aSelector = NSSelectorFromString(@"keychainAttributesWithKey:userId:error:");
    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:[mStore methodSignatureForSelector:aSelector]];
    [inv setSelector:aSelector];
    [inv setTarget:mStore];
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    [inv setArgument:&item atIndex:2];
    NSString* userid = @"юзер@екзампл.ком";
    [inv setArgument:&userid atIndex:3];
//    [inv setArgument:nil atIndex:4];
    [inv invoke];
    
}

//A wrapper around addOrUpdateItem, checks automatically for errors.
//Works on single threaded environment only, as it checks the counts:
#define ADD_OR_UPDATE_ITEM(_item, _expectAdd) \
{\
    ADAuthenticationError* error; \
    long count = [self count]; \
    [mStore addOrUpdateItem:_item error:&error]; \
    ADAssertNoError; \
    if (_expectAdd) { ADAssertLongEquals(count + 1, [self count]); } \
    else { ADAssertLongEquals(count, [self count]); } \
    [self verifyCacheContainsItem:_item]; \
}

//Esnures that two keys are the same:
#define VERIFY_SAME_WITH_KEY(_key1, _key2) \
{\
    XCTAssertNotNil(_key1);\
    XCTAssertNotNil(_key2);\
    ADAssertStringEquals(_key1.authority, _key2.authority);\
    ADAssertStringEquals(_key1.resource, _key2.resource);\
    ADAssertStringEquals(_key1.clientId, _key2.clientId);\
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
        _newItem.userInformation = [ADUserInformation userInformationWithUserId:_newUser error:&error]; \
        ADAssertNoError; \
    } \
    else \
    { \
        _newItem.userInformation = nil; \
    } \
} \

//Verifies that the items in the cache are copied, so that the developer
//cannot accidentally modify them. The method tests the getters too.
-(void) testCopySingleObject
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    ADAuthenticationError* error;
    ADD_OR_UPDATE_ITEM(item, YES);

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

-(void) testComplex
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error;
    XCTAssertNotNil([mStore allItems:&error]);
    ADAssertNoError;
    ADTokenCacheStoreItem* item1 = [self adCreateCacheItem];
    
    //one item:
    ADD_OR_UPDATE_ITEM(item1, YES);
    
    //add the same item and ensure that the counts do not change:
    ADD_OR_UPDATE_ITEM(item1, NO);
    
    //add an item with the same key, but some other change:
    ADTokenCacheStoreItem* item3 = [self adCreateCacheItem];
    item3.accessToken = @"another token";
    ADD_OR_UPDATE_ITEM(item3, NO);

    //Add an item with the same key, but different user:
    ADTokenCacheStoreItem* item4 = nil;
    COPY_ITEM_WITH_NEW_USER(item4, item1, @"   another user   ");
    ADD_OR_UPDATE_ITEM(item4, YES);
    
    //Add an item with nil user:
    ADTokenCacheStoreItem* item5 = nil;
    COPY_ITEM_WITH_NEW_USER(item5, item1, nil);
    ADD_OR_UPDATE_ITEM(item5, YES);
    
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Now few getters:
    ADTokenCacheStoreItem* itemReturn5 = [mStore getItemWithKey:key error:&error];
    ADAssertLongEquals(AD_ERROR_MULTIPLE_USERS, error.code);
    XCTAssertNil(itemReturn5);
    error = nil;//Clear
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    
    NSArray* array = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertTrue(array.count == 3);
    
    //Now test the removers:
    [mStore removeItemWithKey:key error:&error];//Specific user
    ADAssertNoError;
    
    array = [mStore allItems:&error];
    XCTAssertTrue(array.count == 2);
    
    //This will remove two elements, as the userId is not specified:
    [mStore removeItemWithKey:key error:&error];
    ADAssertNoError;
    XCTAssertTrue([self count]  == 1);
    
    [mStore removeAll:&error];
    ADAssertNoError;
    array = [mStore allItems:&error];
    ADAssertNoError;
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 0);
}

//Add large number of items to the cache. Acts as a mini-stress test too
//Checks that the persistence catches up and that the number of persistence operations is
//disproportionately smaller than the cache updates:
-(void) testBulkPersistence
{
    long numItems = 500;//Keychain is relatively slow
    ADTokenCacheStoreItem* original = [self adCreateCacheItem];
    NSMutableArray* allItems = [NSMutableArray new];
    for (long i = 0; i < numItems; ++i)
    {
        NSString* user = [NSString stringWithFormat:@"User: %ld", i];
        ADTokenCacheStoreItem* item = nil;
        COPY_ITEM_WITH_NEW_USER(item, original, user);
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

-(void) verifyCacheContainsItem: (ADTokenCacheStoreItem*) item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    
    ADTokenCacheStoreItem* read = [mStore getItemWithKey:key error:&error];
    ADAssertNoError;
    XCTAssertEqualObjects(item, read);
}

-(void) testInitializer
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADKeychainTokenCacheStore* simple = [ADKeychainTokenCacheStore new];
    XCTAssertNotNil(simple);
    XCTAssertNotNil(simple.sharedGroup);
    NSString* group = @"test";
    ADKeychainTokenCacheStore* withGroup = [[ADKeychainTokenCacheStore alloc] initWithGroup:group];
    XCTAssertNotNil(withGroup);
}

-(void) testsharedKeychainGroupProperty
{
    //Put an item in the cache:
    ADAssertLongEquals(0, [self count]);
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    ADAuthenticationError* error = nil;
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    ADAssertLongEquals(1, [self count]);
    
    //Test the property:
    ADAuthenticationSettings* settings = [ADAuthenticationSettings sharedInstance];
    ADKeychainTokenCacheStore* keychainStore = (ADKeychainTokenCacheStore*)mStore;
    XCTAssertNotNil(settings.sharedCacheKeychainGroup);
    XCTAssertNotNil(keychainStore.sharedGroup);
    NSString* groupName = @"com.microsoft.ADAL";
    settings.sharedCacheKeychainGroup = groupName;
    ADAssertStringEquals(settings.sharedCacheKeychainGroup, groupName);
    XCTAssertTrue([mStore isKindOfClass:[ADKeychainTokenCacheStore class]]);
    ADAssertStringEquals(keychainStore.sharedGroup, groupName);
    
    //Restore back to default
    keychainStore.sharedGroup = nil;
    XCTAssertNil(keychainStore.sharedGroup);
    XCTAssertNil(settings.sharedCacheKeychainGroup);
    [mStore removeAll:&error];
    ADAssertNoError;
    ADAssertLongEquals(0, [self count]);
}

@end
