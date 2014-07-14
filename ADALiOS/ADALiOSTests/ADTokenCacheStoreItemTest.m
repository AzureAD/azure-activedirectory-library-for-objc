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
#import "../ADALiOS/ADAuthenticationContext.h"

@interface ADTokenCacheStoreItemTest : XCTestCase

@end

@implementation ADTokenCacheStoreItemTest

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
    [self adTestEnd];
    [super tearDown];
}


-(void) testIsExpired
{
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
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
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    XCTAssertFalse(item.isEmptyUser);
    item.userInformation = nil;
    XCTAssertTrue(item.isEmptyUser);
    item = [ADTokenCacheStoreItem new];
    XCTAssertTrue(item.isEmptyUser, "The default item should not have a user.");
}

-(void) verifySameUser: (NSString*) userId1
               userId2: (NSString*) userId2
{
    ADAuthenticationError* error;
    
    ADTokenCacheStoreItem* item1 = [self adCreateCacheItem];
    if (userId1)
    {
        item1.userInformation = [ADUserInformation userInformationWithUserId:userId1 error:&error];
        ADAssertNoError;
        XCTAssertNotNil(item1.userInformation);
    }
    else
    {
        item1.userInformation = nil;
    }
    
    ADTokenCacheStoreItem* item2 = [self adCreateCacheItem];
    if (userId2)
    {
        item2.userInformation = [ADUserInformation userInformationWithUserId:userId2 error:&error];
        ADAssertNoError;
        XCTAssertNotNil(item2.userInformation);
    }
    else
    {
        item2.userInformation = nil;
    }
    
    XCTAssertTrue([item1 isSameUser:item2], "Should be the same: '%@' and '%@", userId1, userId2);
    XCTAssertTrue([item2 isSameUser:item1], "Should be the same: '%@' and '%@", userId1, userId2);
}

-(void)testIsSameUser
{
    //Check the trivial cases:
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    XCTAssertTrue([item isSameUser:item]);//self
    ADTokenCacheStoreItem* copy = [item copy];
    XCTAssertTrue([item isSameUser:copy]);
    XCTAssertTrue([copy isSameUser:item]);
    
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:@"Another user   " error:&error];
    ADAssertNoError;
    XCTAssertNotNil(item.userInformation);
    XCTAssertFalse([item isSameUser:copy]);
    XCTAssertFalse([copy isSameUser:item]);
    
    copy.userInformation = nil;
    XCTAssertFalse([item isSameUser:copy]);
    XCTAssertFalse([copy isSameUser:item]);
    
    [self verifySameUser:nil userId2:nil];
    [self verifySameUser:@" test user" userId2:@"test user"];
    [self verifySameUser:@" test user  " userId2:@"     test user     "];
    [self verifySameUser:@" test user" userId2:@"test user     "];
    [self verifySameUser:@"test user" userId2:@"test user"];
}

-(void) testMultiRefreshTokens
{
    ADTokenCacheStoreItem* item = [self adCreateCacheItem];
    XCTAssertFalse(item.multiResourceRefreshToken);
    item.resource = nil;
    XCTAssertFalse(item.multiResourceRefreshToken);
    
    //Valid:
    item.accessToken = nil;
    XCTAssertTrue(item.multiResourceRefreshToken);
    
    //Invalidate through refresh token:
    item.refreshToken = nil;
    XCTAssertFalse(item.multiResourceRefreshToken, "nil refresh token");
    item.refreshToken = @"  ";
    XCTAssertFalse(item.multiResourceRefreshToken, "Empty resource token");
    
    //Restore:
    item.refreshToken = @"refresh token";
    XCTAssertTrue(item.multiResourceRefreshToken);
}

-(void) testSupportsSecureCoding
{
    XCTAssertTrue([ADTokenCacheStoreItem supportsSecureCoding], "Ensure that the unarchiving is secure.");
}

@end
