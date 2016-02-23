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
#import "ADAuthenticationContext.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserInformation.h"

@interface ADTokenCacheItemTests : XCTestCase

@end

@implementation ADTokenCacheItemTests

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


- (void)testIsExpired
{
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
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
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
    XCTAssertFalse(item.isEmptyUser);
    item.userInformation = nil;
    XCTAssertTrue(item.isEmptyUser);
    item = [ADTokenCacheItem new];
    XCTAssertTrue(item.isEmptyUser, "The default item should not have a user.");
}

- (void)verifySameUser:(NSString *)userId1
               userId2:(NSString *)userId2
{
    ADTokenCacheItem* item1 = [self adCreateCacheItem:userId1];
    ADTokenCacheItem* item2 = [self adCreateCacheItem:userId2];
    
    XCTAssertTrue([item1 isSameUser:item2], "Should be the same: '%@' and '%@", userId1, userId2);
    XCTAssertTrue([item2 isSameUser:item1], "Should be the same: '%@' and '%@", userId1, userId2);
}

-(void)testIsSameUser
{
    [self verifySameUser:nil userId2:nil];
    [self verifySameUser:@" test user" userId2:@"test user"];
    [self verifySameUser:@" test user  " userId2:@"     test user     "];
    [self verifySameUser:@" test user" userId2:@"test user     "];
    [self verifySameUser:@"test user" userId2:@"test user"];
}

-(void) testMultiRefreshTokens
{
    ADTokenCacheItem* item = [self adCreateCacheItem:@"eric@contoso.com"];
    XCTAssertFalse(item.isMultiResourceRefreshToken);
    item.resource = nil;
    XCTAssertFalse(item.isMultiResourceRefreshToken);
    
    //Valid:
    item.accessToken = nil;
    XCTAssertTrue(item.isMultiResourceRefreshToken);
    
    //Invalidate through refresh token:
    item.refreshToken = nil;
    XCTAssertFalse(item.isMultiResourceRefreshToken, "nil refresh token");
    item.refreshToken = @"  ";
    XCTAssertFalse(item.isMultiResourceRefreshToken, "Empty resource token");
    
    //Restore:
    item.refreshToken = @"refresh token";
    XCTAssertTrue(item.isMultiResourceRefreshToken);
}

- (void)testSupportsSecureCoding
{
    XCTAssertTrue([ADTokenCacheItem supportsSecureCoding], "Ensure that the unarchiving is secure.");
}

// Round trip the item though NSKeyedArchiver and NSKeyedUnarchiver to ensure the initWithCoder: and
// encodeWithCoder: are properly implemented.
- (void)testCoder
{
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    XCTAssertNotNil(item);
    XCTAssertNotEqual([item hash], 0);
    
    NSData* data = [NSKeyedArchiver archivedDataWithRootObject:item];
    XCTAssertNotNil(data);
    
    ADTokenCacheItem* unarchivedItem = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    XCTAssertNotNil(unarchivedItem);
    
    XCTAssertEqualObjects(item, unarchivedItem);
    XCTAssertEqual([item hash], [unarchivedItem hash]);
}

- (void)testCopyWithZone
{
    ADTokenCacheItem* item = [self adCreateATCacheItem];
    XCTAssertNotNil(item);
    XCTAssertNotEqual([item hash], 0);
    NSZone* zone = NSDefaultMallocZone();
    
    ADTokenCacheItem* copy = [item copyWithZone:zone];
    XCTAssertNotNil(copy);
    XCTAssertEqualObjects(copy, item);
    XCTAssertEqual([copy hash], [item hash]);
}

@end
