//
//  ADTokenCacheStoreItemTest.m
//  ADALiOS
//
//  Created by Boris Vidolov on 11/14/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import <ADALiOS/ADTokenCacheStoreItem.h>

@interface ADTokenCacheStoreItemTest : XCTestCase

@end

@implementation ADTokenCacheStoreItemTest

- (void)setUp
{
    [super setUp];
    // Put setup code here; it will be run once, before the first test case.
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [super tearDown];
}


-(void) testIsExpired
{
    ADTokenCacheStoreItem* item = [self createCacheItem];
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
    ADTokenCacheStoreItem* item = [self createCacheItem];
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
    
    ADTokenCacheStoreItem* item1 = [self createCacheItem];
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
    
    ADTokenCacheStoreItem* item2 = [self createCacheItem];
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
    ADTokenCacheStoreItem* item = [self createCacheItem];
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

@end
