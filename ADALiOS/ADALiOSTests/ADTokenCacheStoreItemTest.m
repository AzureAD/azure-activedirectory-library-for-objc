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
#import "../ADALiOS/public/ADAuthenticationContext.h"

@interface ADTokenCacheStoreItemTest : XCTestCase

@end

@implementation ADTokenCacheStoreItemTest

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


- (void)testIsExpired
{
    ADTokenCacheStoreItem* item = [[ADTestUtils defaultUtils] createCacheItem:nil];
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:0];
    XCTAssertTrue(item.isExpired, "When time is now, the item should expire.");
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    XCTAssertTrue(item.isExpired, "The device clock can be off by a minute, so we should have enough buffer.");
    item.expiresOn = nil;
    XCTAssertTrue(!item.isExpired, "No expiration time.");
    item.expiresOn = [NSDate distantFuture];
    XCTAssertTrue(!item.isExpired, "The item will expire outside of my lifetime!");
    item.expiresOn = [NSDate distantPast];
    XCTAssertTrue(item.isExpired, "The item expired when the dinosaurs lived!");
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:3600];
    XCTAssertTrue(!item.isExpired, "The item is good for one more hour!");
}
- (void)testIsEmptyUser
{
    ADTokenCacheStoreItem* item = [[ADTestUtils defaultUtils] createCacheItem:nil];
    XCTAssertFalse(item.isEmptyUser);
    item.profileInfo = nil;
    XCTAssertTrue(item.isEmptyUser);
    item = [ADTokenCacheStoreItem new];
    XCTAssertTrue(item.isEmptyUser, "The default item should not have a user.");
}

- (void)verifySameUser:(NSString*)userId1
               userId2:(NSString*)userId2
{
    ADAuthenticationError* error;
    
    ADTokenCacheStoreItem* item1 = [[ADTestUtils defaultUtils] createCacheItem:nil];
    if (userId1)
    {
        item1.profileInfo = [ADProfileInfo profileInfoWithUsername:userId1 error:&error];
        ADAssertNoError;
        XCTAssertNotNil(item1.profileInfo);
    }
    else
    {
        item1.profileInfo = nil;
    }
    
    ADTokenCacheStoreItem* item2 = [[ADTestUtils defaultUtils] createCacheItem:nil];
    if (userId2)
    {
        item2.profileInfo = [ADProfileInfo profileInfoWithUsername:userId2 error:&error];
        ADAssertNoError;
        XCTAssertNotNil(item2.profileInfo);
    }
    else
    {
        item2.profileInfo = nil;
    }
    
    XCTAssertTrue([item1 isSameUser:item2], "Should be the same: '%@' and '%@", userId1, userId2);
    XCTAssertTrue([item2 isSameUser:item1], "Should be the same: '%@' and '%@", userId1, userId2);
}

- (void)testIsSameUser
{
    //Check the trivial cases:
    NSString* errorDetails = nil;
    ADTokenCacheStoreItem* item = [[ADTestUtils defaultUtils] createCacheItem:&errorDetails];
    XCTAssertNotNil(item, @"Failed to create item: %@", errorDetails);
    XCTAssertTrue([item isSameUser:item]);//self
    ADTokenCacheStoreItem* copy = [item copy];
    XCTAssertTrue([item isSameUser:copy]);
    XCTAssertTrue([copy isSameUser:item]);
    
    ADAuthenticationError* error;
    item.profileInfo = [ADProfileInfo profileInfoWithUsername:@"Another user   " error:&error];
    ADAssertNoError;
    XCTAssertNotNil(item.profileInfo);
    XCTAssertFalse([item isSameUser:copy]);
    XCTAssertFalse([copy isSameUser:item]);
    
    copy.profileInfo = nil;
    XCTAssertFalse([item isSameUser:copy]);
    XCTAssertFalse([copy isSameUser:item]);
    
    [self verifySameUser:nil userId2:nil];
    [self verifySameUser:@" test user" userId2:@"test user"];
    [self verifySameUser:@" test user  " userId2:@"     test user     "];
    [self verifySameUser:@" test user" userId2:@"test user     "];
    [self verifySameUser:@"test user" userId2:@"test user"];
}

-(void) testSupportsSecureCoding
{
    XCTAssertTrue([ADTokenCacheStoreItem supportsSecureCoding], "Ensure that the unarchiving is secure.");
}

@end
