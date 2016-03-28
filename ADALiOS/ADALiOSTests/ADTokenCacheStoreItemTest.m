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

- (void)testV1BackCompatData
{
    NSString* base64String = @"YnBsaXN0MDDUAQIDBAUGhodYJHZlcnNpb25YJG9iamVjdHNZJGFyY2hpdmVyVCR0b3ASAAGGoK8QKwcIGxwdHh8gJCo0OD0+YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6foJVJG51bGzZCQoLDA0ODxAREhMUFRYXGBkaViRjbGFzc1lhdXRob3JpdHlYcmVzb3VyY2VfEA91c2VySW5mb3JtYXRpb25ZZXhwaXJlc09uWGNsaWVudElkXHJlZnJlc2hUb2tlblthY2Nlc3NUb2tlbl8QD2FjY2Vzc1Rva2VuVHlwZYAqgAKAAIAJgAeAA4AGgASABV8QKGh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS9jb21tb25fECQyN0FEODNDOS1GQzA1LTRBNkMtQUYwMS0zNkVEQTQyRUQxOEZePGFjY2VzcyB0b2tlbj5WQmVhcmVyXxAPPHJlZnJlc2ggdG9rZW4+0iEJIiNXTlMudGltZSNBLoSAAAAAAIAI0iUmJyhaJGNsYXNzbmFtZVgkY2xhc3Nlc1ZOU0RhdGWiJylYTlNPYmplY3TVKywtLgkvMDEyM18QEXVzZXJJZERpc3BsYXlhYmxlWWFsbENsYWltc1pyYXdJZFRva2VuVnVzZXJJZAmADYAMgAqAKdIJNTY3WU5TLnN0cmluZ4ALXxAWbXlmYWtldXNlckBjb250b3NvLmNvbdIlJjk6XxAPTlNNdXRhYmxlU3RyaW5nozs8KV8QD05TTXV0YWJsZVN0cmluZ1hOU1N0cmluZ18RAlBleUowZVhBaU9pSktWMVFpTENKaGRXUWlPaUpqTTJNM1pqVmxOUzAzTVRVekxUUTBaRFF0T1RCbE5pMHpNamsyT0Raa05EaGtOellpTENKcGMzTWlPaUpvZEhSd2N6b3ZMM04wY3k1M2FXNWtiM2R6TG01bGRDODJabVF4WmpWalpDMWhPVFJqTFRRek16VXRPRGc1WWkwMll6VTVPR1UyWkRnd05EZ3ZJaXdpYVdGMElqb3hNemczTWpJME1UWTVMQ0p1WW1ZaU9qRXpPRGN5TWpReE5qa3NJbVY0Y0NJNk1UTTROekl5TnpjMk9Td2lkbVZ5SWpvaU1TNHdJaXdpZEdsa0lqb2lObVprTVdZMVkyUXRZVGswWXkwME16TTFMVGc0T1dJdE5tTTFPVGhsTm1RNE1EUTRJaXdpYjJsa0lqb2lOVE5qTm1GalpqSXRNamMwTWkwME5UTTRMVGt4T0dRdFpUYzRNalUzWldNNE5URTJJaXdpZFhCdUlqb2liWGxtWVd0bGRYTmxja0JqYjI1MGIzTnZMbU52YlNJc0luVnVhWEYxWlY5dVlXMWxJam9pYlhsbVlXdGxkWE5sY2tCamIyNTBiM052TG1OdmJTSXNJbk4xWWlJNklqQkVlRzVCYkV4cE1USkpka2RNWDJSSE0yUkVUV3N6ZW5BMlFWRklibXBuYjJkNWFXMDFRVmR3VTJNaUxDSm1ZVzFwYkhsZmJtRnRaU0k2SWxWelpYSWlMQ0puYVhabGJsOXVZVzFsSWpvaVJtRnJaU0o50z9ACUFQX1dOUy5rZXlzWk5TLm9iamVjdHOuQkNERUZHSElKS0xNTk+ADoAPgBCAEYASgBOAFIAVgBaAF4AYgBmAGoAbrlFSU1RVVldYUlpbXFFegByAHYAegB+AIIAhgCKAI4AdgCSAJYAmgByAJ4AoU3VwblNuYmZTZXhwU2lzc1NvaWRTdHlwU3ZlclNhdWRTaWF0W2ZhbWlseV9uYW1lU3N1YlN0aWRbdW5pcXVlX25hbWVaZ2l2ZW5fbmFtZV8QFm15ZmFrZXVzZXJAY29udG9zby5jb20SUq9caRJSr2p5XxA9aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4L18QJDUzYzZhY2YyLTI3NDItNDUzOC05MThkLWU3ODI1N2VjODUxNlNKV1RTMS4wXxAkYzNjN2Y1ZTUtNzE1My00NGQ0LTkwZTYtMzI5Njg2ZDQ4ZDc2VFVzZXJfECswRHhuQWxMaTEySXZHTF9kRzNkRE1rM3pwNkFRSG5qZ29neWltNUFXcFNjXxAkNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4VEZha2XSJSZ7fFxOU0RpY3Rpb25hcnmifSlcTlNEaWN0aW9uYXJ50iUmf4BfEBFBRFVzZXJJbmZvcm1hdGlvbqKBKV8QEUFEVXNlckluZm9ybWF0aW9u0iUmg4RfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW2ihSlfEBVBRFRva2VuQ2FjaGVTdG9yZUl0ZW1fEA9OU0tleWVkQXJjaGl2ZXLRiIlUcm9vdIABAAgAEQAaACMALQAyADcAZQBrAH4AhQCPAJgAqgC0AL0AygDWAOgA6gDsAO4A8ADyAPQA9gD4APoBJQFMAVsBYgF0AXkBgQGKAYwBkQGcAaUBrAGvAbgBwwHXAeEB7AHzAfQB9gH4AfoB/AIBAgsCDQImAisCPQJBAlMCXASwBLcEvwTKBNkE2wTdBN8E4QTjBOUE5wTpBOsE7QTvBPEE8wT1BQQFBgUIBQoFDAUOBRAFEgUUBRYFGAUaBRwFHgUgBSIFJgUqBS4FMgU2BToFPgVCBUYFUgVWBVoFZgVxBYoFjwWUBdQF+wX/BgMGKgYvBl0GhAaJBo4GmwaeBqsGsAbEBscG2wbgBvgG+wcTByUHKActAAAAAAAAAgEAAAAAAAAAigAAAAAAAAAAAAAAAAAABy8=";
    
    NSData* itemData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    XCTAssertNotNil(itemData);
    ADTokenCacheStoreItem* item = [NSKeyedUnarchiver unarchiveObjectWithData:itemData];
    XCTAssertNotNil(item);
    
    XCTAssertEqualObjects(item.authority, @"https://login.microsoftonline.com/common");
    XCTAssertEqualObjects(item.accessToken, @"<access token>");
    XCTAssertEqualObjects(item.accessTokenType, @"Bearer");
    XCTAssertEqualObjects(item.refreshToken, @"<refresh token>");
    XCTAssertEqualObjects(item.clientId, @"27AD83C9-FC05-4A6C-AF01-36EDA42ED18F");
    XCTAssertEqualObjects(item.expiresOn, [NSDate dateWithTimeIntervalSinceReferenceDate:1000000]);
    XCTAssertEqualObjects(item.userInformation.userId, @"myfakeuser@contoso.com");
    
    NSString* originalIdToken = @"eyJ0eXAiOiJKV1QiLCJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoibXlmYWtldXNlckBjb250b3NvLmNvbSIsInVuaXF1ZV9uYW1lIjoibXlmYWtldXNlckBjb250b3NvLmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlVzZXIiLCJnaXZlbl9uYW1lIjoiRmFrZSJ9";
    XCTAssertEqualObjects(item.userInformation.rawIdToken, originalIdToken);
    
}


@end
