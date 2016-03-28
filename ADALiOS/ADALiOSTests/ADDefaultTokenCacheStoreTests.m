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
#import "ADKeychainTokenCacheStore.h"
#import "ADTokenCacheStoring.h"

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
    
    [ADAuthenticationSettings sharedInstance].sharedCacheKeychainGroup = [[NSBundle mainBundle] bundleIdentifier];
    mStore = (ADKeychainTokenCacheStore*)[ADAuthenticationSettings sharedInstance].defaultTokenCacheStore;
    XCTAssertNotNil(mStore, "Default store cannot be nil.");
    XCTAssertTrue([mStore isKindOfClass:[ADKeychainTokenCacheStore class]]);
    [mStore removeAllWithError:nil];//Start clean before each test
}

- (void)tearDown
{
    [mStore removeAllWithError:nil];//Attempt to clear the junk from the keychain
    mStore = nil;
    
    [self adTestEnd];
    [super tearDown];
}

-(long) count
{
    ADAuthenticationError* error;
    NSArray* all = [mStore allItemsWithError:&error];
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
-(void) addOrUpdateItem: (ADTokenCacheStoreItem*) item expectAdd: (BOOL) expectAdd
{
    ADAuthenticationError* error;
    long count = [self count];
    [mStore addOrUpdateItem:item error:&error];
    ADAssertNoError;
    if (expectAdd)
    {
        ADAssertLongEquals(count + 1, [self count]);
    }
    else
    {
        ADAssertLongEquals(count, [self count]);
    }
    [self verifyCacheContainsItem:item];
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
    [self adVerifySameWithItem:item item2:newItem];
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

//Verifies consistency and copying between what was passed from the cache,
//what is stored and what is returned:
- (void)verifyCopyingWithItem: (ADTokenCacheStoreItem*) original
                         copy: (ADTokenCacheStoreItem*) copy
{
    XCTAssertNotEqualObjects(original, copy, "The item was not copied.");
    [self adVerifySameWithItem:original item2:copy];
}

//Verifies that the items in the cache are copied, so that the developer
//cannot accidentally modify them. The method tests the getters too.
-(void) testCopySingleObject
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    ADAuthenticationError* error;
    [self addOrUpdateItem:item expectAdd:YES];

    //getItemWithKey:userId
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    XCTAssertNotNil(key);
    ADTokenCacheStoreItem* exact = [mStore getItemWithKey:key userId:item.userInformation.userId error:&error];
    ADAssertNoError;
    [self verifyCopyingWithItem:item copy:exact];

    //getItemsWithKey:userId and nil userId:
    ADTokenCacheStoreItem* returnedItemForNil = [mStore getItemWithKey:key userId:nil error:&error];
    ADAssertNoError;
    XCTAssertNotNil(returnedItemForNil);
    [self verifyCopyingWithItem:item copy:returnedItemForNil];
    [self verifyCopyingWithItem:exact copy:returnedItemForNil];

    //getItemsWithKey:
    NSArray* items = [mStore getItemsWithKey:key error:&error];
    ADAssertNoError;
    XCTAssertTrue(items.count == 1);
    ADTokenCacheStoreItem* returnedFromArray = [items objectAtIndex:0];
    XCTAssertNotNil(returnedFromArray);
    [self verifyCopyingWithItem:item copy:returnedFromArray];
    [self verifyCopyingWithItem:returnedItemForNil copy:returnedFromArray];
    
    //allItems:
    NSArray* allItems = [mStore allItemsWithError:&error];
    ADAssertNoError;
    XCTAssertTrue(items.count == 1);
    ADTokenCacheStoreItem* returnedFromAll = [allItems objectAtIndex:0];
    XCTAssertNotNil(returnedFromAll);
    [self verifyCopyingWithItem:item copy:returnedFromAll];
    [self verifyCopyingWithItem:returnedFromArray copy:returnedFromAll];
}

- (void)verifyTwoItems: (ADTokenCacheStoreItem*) item1
                 item2: (ADTokenCacheStoreItem*) item2
                 array: (NSArray*) array
{
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 2);
    for(ADTokenCacheStoreItem* item in array)
    {
        XCTAssertNotEqualObjects(item, item1);
        XCTAssertNotEqualObjects(item, item2);
        if ([item.userInformation.userId isEqualToString:item1.userInformation.userId])
        {
            [self verifyCopyingWithItem:item1 copy:item];
        }
        else
        {
            ADAssertStringEquals(item2.userInformation.userId, item.userInformation.userId);
            [self verifyCopyingWithItem:item2 copy:item];
        }
    }
}

//Adds more than one object for a given key and verifies that extraction copies correctly
//Tests al of the getters:
-(void) testCopyMultipleObjects
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADTokenCacheStoreItem* item1 = [self adCreateCacheItem];
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    [self addOrUpdateItem:item1 expectAdd:YES];
    
    ADTokenCacheStoreItem* item2 = [self copyItem:item1 withNewUser:@"  another user  "];
    //We will use the otherKey later to ensure that the getters work with any proper key object.
    ADTokenCacheStoreKey* otherKey = [item2 extractKeyWithError:&error];
    ADAssertNoError;
    [self verifySameWithKey:key key2:otherKey];
    [self addOrUpdateItem:item2 expectAdd:YES];
    
    //getItemsWithKey
    NSArray* allWithKey = [mStore getItemsWithKey:otherKey error:&error];
    ADAssertNoError;
    [self verifyTwoItems:item1 item2:item2 array:allWithKey];

    //Individual items with the userId:
    ADTokenCacheStoreItem* item1Return = [mStore getItemWithKey:key userId:item1.userInformation.userId error:&error];
    ADAssertNoError;
    [self verifyCopyingWithItem:item1 copy:item1Return];
    ADTokenCacheStoreItem* item2Return = [mStore getItemWithKey:otherKey userId:item2.userInformation.userId error:&error];
    ADAssertNoError;
    [self verifyCopyingWithItem:item2 copy:item2Return];

    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //get item with id of nil:
    ADTokenCacheStoreItem* itemReturn = [mStore getItemWithKey:otherKey userId:nil error:&error];
    ADAssertLongEquals(AD_ERROR_MULTIPLE_USERS, error.code);
    XCTAssertNil(itemReturn);
}

-(void) testComplex
{
    XCTAssertTrue([self count] == 0, "Start empty.");
    
    ADAuthenticationError* error;
    XCTAssertNotNil([mStore allItemsWithError:&error]);
    ADAssertNoError;
    ADTokenCacheStoreItem* item1 = [self adCreateCacheItem];
    
    //one item:
    [self addOrUpdateItem:item1 expectAdd:YES];
    
    //add the same item and ensure that the counts do not change:
    [self addOrUpdateItem:item1 expectAdd:NO];
    
    //Add an item with different key:
    ADTokenCacheStoreItem* item2 = [self adCreateCacheItem];
    item2.resource = @"another authority";
    [self addOrUpdateItem:item2 expectAdd:YES];
    
    //add an item with the same key, but some other change:
    ADTokenCacheStoreItem* item3 = [self adCreateCacheItem];
    item3.accessToken = @"another token";
    [self addOrUpdateItem:item3 expectAdd:NO];

    //Add an item with the same key, but different user:
    ADTokenCacheStoreItem* item4 = [self copyItem:item1 withNewUser:@"   another user   "];
    [self addOrUpdateItem:item4 expectAdd:YES];
    
    //Add an item with nil user:
    ADTokenCacheStoreItem* item5 = [self copyItem:item1 withNewUser:nil];
    [self addOrUpdateItem:item5 expectAdd:YES];
    
    ADTokenCacheStoreKey* key = [item1 extractKeyWithError:&error];
    ADAssertNoError;
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Now few getters:
    ADTokenCacheStoreItem* itemReturn5 = [mStore getItemWithKey:key userId:nil error:&error];
    ADAssertLongEquals(AD_ERROR_MULTIPLE_USERS, error.code);
    XCTAssertNil(itemReturn5);
    error = nil;//Clear
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    
    NSArray* array = [mStore getItemsWithKey:key error:&error];
    ADAssertNoError;
    XCTAssertTrue(array.count == 3);
    
    //Now test the removers:
    [mStore removeItemWithKey:key userId:item4.userInformation.userId error:&error];//Specific user
    ADAssertNoError;
    XCTAssertTrue(array.count == 3);
    
    //This will remove two elements, as the userId is not specified:
    [mStore removeItemWithKey:key userId:nil error:&error];
    ADAssertNoError;
    XCTAssertTrue([self count]  == 1);
    
    [mStore removeAllWithError:&error];
    ADAssertNoError;
    array = [mStore allItemsWithError:&error];
    ADAssertNoError;
    XCTAssertNotNil(array);
    XCTAssertTrue(array.count == 0);
}

-(void) threadProc
{
    @autoreleasepool//Autorelease pool for the whole thread. Required.
    {
        //Create as much date as possible outside of the run loop to cause the most
        //thread contentions in the loop:
        ADTokenCacheStoreItem* item1 = [self adCreateCacheItem];
        ADAuthenticationError* error;
        item1.userInformation = [ADUserInformation userInformationWithUserId:@"foo" error:nil];
        ADAssertNoError;
        ADTokenCacheStoreItem* item2 = [self adCreateCacheItem];
        item2.userInformation = [ADUserInformation userInformationWithUserId:@"bar" error:nil];
        ADAssertNoError;
        ADTokenCacheStoreItem* item3 = [self adCreateCacheItem];
        item3.userInformation = nil;
        ADTokenCacheStoreKey* key123 = [item3 extractKeyWithError:&error];
        ADAssertNoError;

        ADTokenCacheStoreItem* item4 = [self adCreateCacheItem];
        item4.authority = @"https://www.authority.com/tenant.com";
        ADTokenCacheStoreKey* key4 = [item4 extractKeyWithError:&error];
        ADAssertNoError;
        
        NSDate* end = [NSDate dateWithTimeIntervalSinceNow:sThreadsRunTime];//few seconds into the future
        NSDate* now;
        do
        {
            @autoreleasepool//The cycle will create constantly objects, so it needs its own autorelease pool
            {
                ADAuthenticationError* error;//Keep it local
                [mStore removeAllWithError:&error];
                ADAssertNoError;
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
                NSArray* array = [mStore getItemsWithKey:key123 error:&error];
                ADAssertNoError;
                XCTAssertNotNil(array);
                array = [mStore allItemsWithError:&error];
                ADAssertNoError;
                XCTAssertNotNil(array);
                array = [mStore getItemsWithKey:key4 error:&error];
                ADAssertNoError;
                XCTAssertNotNil(array);
                [mStore getItemWithKey:key123 userId:nil error:&error];
                if (error)//can error or not, depending on the state of deletions
                {
                    ADAssertLongEquals(AD_ERROR_MULTIPLE_USERS, error.code);
                    error = nil;
                }
                ADTokenCacheStoreItem* return1 = [mStore getItemWithKey:key123 userId:item1.userInformation.userId error:&error];
                ADAssertNoError;
                if (return1)//may not return if deleted in another thread
                {
                    [self adVerifySameWithItem:item1 item2:return1];
                }
                ADTokenCacheStoreItem* badUser = [mStore getItemWithKey:key123 userId:@"not real" error:&error];
                ADAssertNoError;
                XCTAssertNil(badUser);
                ADTokenCacheStoreItem* return4 = [mStore getItemWithKey:key4 userId:nil error:&error];//Always exactly 1 or 0 elements for this key
                ADAssertNoError;
                if (return4)
                {
                    [self adVerifySameWithItem:item4 item2:return4];
                }

                badUser = [mStore getItemWithKey:key4 userId:@"not real" error:&error];
                ADAssertNoError;
                XCTAssertNil(badUser);
                [mStore removeItemWithKey:key123 userId:item1.userInformation.userId error:&error];
                ADAssertNoError;
                [mStore removeItemWithKey:key123 userId:item2.userInformation.userId error:&error];
                ADAssertNoError;
                [mStore removeItemWithKey:key123 userId:nil error:&error];
                ADAssertNoError;
                [mStore removeItemWithKey:key4 userId:nil error:&error];
                ADAssertNoError;
                
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
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];//Multi-user errors
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
        ADTokenCacheStoreItem* item = [self copyItem:original withNewUser:user];
        [allItems addObject:item];
    }

    ADAuthenticationError* error = nil;
    for(ADTokenCacheStoreItem* item in allItems)
    {
        [mStore addOrUpdateItem:item error:&error];
        ADAssertNoError;
    }

    //Restore:
    [mStore removeAllWithError:&error];
    ADAssertNoError;
}

-(void) verifyCacheContainsItem: (ADTokenCacheStoreItem*) item
{
    XCTAssertNotNil(item);
    ADAuthenticationError* error;
    ADTokenCacheStoreKey* key = [item extractKeyWithError:&error];
    ADAssertNoError;
    
    ADTokenCacheStoreItem* read = nil;
    if (item.userInformation)
    {
        read = [mStore getItemWithKey:key userId:item.userInformation.userId error:&error];
    }
    else
    {
        //Find the one (if any) that has userId equal to nil:
        NSArray* all = [mStore getItemsWithKey:key error:&error];
        ADAssertNoError;
        XCTAssertNotNil(all);
        for(ADTokenCacheStoreItem* i in all)
        {
            XCTAssertNotNil(i);
            if (!i.userInformation)
            {
                XCTAssertNil(read);
                read = i;
            }
        }
    }
    ADAssertNoError;
    [self adVerifySameWithItem:item item2:read];
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
    NSString* groupName = @"com.microsoft.ADAL";
    settings.sharedCacheKeychainGroup = groupName;
    ADAssertStringEquals(settings.sharedCacheKeychainGroup, groupName);
    XCTAssertTrue([mStore isKindOfClass:[ADKeychainTokenCacheStore class]]);
    ADAssertStringEquals(keychainStore.sharedGroup, groupName);
    
    //Restore back to default
    keychainStore.sharedGroup = [[NSBundle mainBundle] bundleIdentifier];
    [mStore removeAllWithError:&error];
    ADAssertNoError;
    ADAssertLongEquals(0, [self count]);
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
    
    ADKeychainTokenCacheStore* cache = [[ADKeychainTokenCacheStore alloc] initWithGroup:nil];
    ADAuthenticationError* error = nil;
    
    ADTokenCacheStoreKey* key = [ADTokenCacheStoreKey keyWithAuthority:@"https://login.microsoftonline.com/common"
                                                    resource:@"<resource>"
                            // Client ID is upper cased here to make sure it does the proper case conversion
                                                    clientId:@"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F"
                                                       error:&error];
    XCTAssertNotNil(key);
    
    ADTokenCacheStoreItem* item = [cache getItemWithKey:key userId:@"myfakeuser@contoso.com" error:&error];
    XCTAssertNotNil(item);
    
    XCTAssertEqualObjects(item.accessToken, @"<access token>");
    XCTAssertEqualObjects(item.refreshToken, @"<refresh token>");
    XCTAssertEqualObjects(item.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(item.userInformation.userId, @"myfakeuser@contoso.com");
    
    NSDictionary* deleteQuery = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                                   (id)kSecAttrAccount : @"myfakeuser@contoso.com",
                                   (id)kSecAttrService : service,
                                   (id)kSecAttrGeneric : @"MSOpenTech.ADAL.1",
                                   };
    
    SecItemDelete((CFDictionaryRef)deleteQuery);
}

@end
