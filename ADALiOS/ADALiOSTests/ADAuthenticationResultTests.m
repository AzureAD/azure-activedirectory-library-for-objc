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
#import "../ADALiOS/ADAuthenticationContext.h"
#import "../ADALiOS/ADAuthenticationResult+Internal.h"
#import "../ADALiOS/ADTokenCacheStoreItem.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTestUtils.h"

@interface ADAuthenticationResultTests : XCTestCase

@end

@implementation ADAuthenticationResultTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//Only static creators and internal initializers are supported. init and new should throw.
- (void) testInitAndNew
{
    XCTAssertThrows([[ADAuthenticationResult alloc] init]);
    XCTAssertThrows([ADAuthenticationResult new]);
}

#define VERIFY_ERROR_RESULT(_result, _code) \
{ \
    XCTAssertNotNil(_result); \
    ADAuthenticationResultStatus expected = (_code == AD_ERROR_USER_CANCEL) ? AD_USER_CANCELLED : AD_FAILED; \
    XCTAssertEqual(_result.status, expected, "Wrong status on cancellation"); \
    XCTAssertNotNil(_result.error, "Nil error"); \
    ADAssertLongEquals(_result.error.code, _code); \
    XCTAssertNil(_result.tokenCacheStoreItem.accessToken); \
    XCTAssertNil(_result.tokenCacheStoreItem.accessTokenType); \
    XCTAssertNil(_result.tokenCacheStoreItem.refreshToken); \
    XCTAssertNil(_result.tokenCacheStoreItem.expiresOn); \
    XCTAssertNil(_result.tokenCacheStoreItem.profileInfo); \
}

- (void)testResultFromCancellation
{
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromCancellation];
    VERIFY_ERROR_RESULT(result, AD_ERROR_USER_CANCEL);
}

- (void)testResultFromError
{
    ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"something"];
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
    VERIFY_ERROR_RESULT(result, AD_ERROR_UNEXPECTED);
    XCTAssertEqualObjects(result.error, error, "Different error object in the result.");
}

- (void)testResultFromTokenCacheStoreItem
{
    ADAuthenticationResult* nilItemResult = [ADAuthenticationResult resultFromTokenCacheStoreItem:nil];
    VERIFY_ERROR_RESULT(nilItemResult, AD_ERROR_UNEXPECTED);
    
    ADTestUtils* utils = [[ADTestUtils alloc] init];
    utils.authority = @"https://login.windows.net/mytennant.com";
    utils.clientId = @"clientId";
    utils.accessToken = @"accessToken";
    utils.accessTokenType = @"tokenType";
    utils.refreshToken = @"refreshToken";
    utils.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    
    NSString* errorDetails = nil;
    ADTokenCacheStoreItem* item = [utils createCacheItem:&errorDetails];
    XCTAssertNotNil(item, @"Failed to create cache item: %@", errorDetails);
    
    //Copy the item to ensure that it is not modified withing the method call below:
    ADAuthenticationResult* resultFromValidItem = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    XCTAssertNotNil(resultFromValidItem);
    XCTAssertEqual(resultFromValidItem.status, AD_SUCCEEDED, "Result should be success.");
    XCTAssertNil(resultFromValidItem.error, "Unexpected error object: %@", resultFromValidItem.error.errorDetails);
    XCTAssertEqualObjects(item.accessTokenType, resultFromValidItem.tokenCacheStoreItem.accessTokenType);
    XCTAssertEqualObjects(item.accessToken, resultFromValidItem.tokenCacheStoreItem.accessToken);
    XCTAssertEqualObjects(item.expiresOn, resultFromValidItem.tokenCacheStoreItem.expiresOn);
    XCTAssertEqualObjects(item.profileInfo.tenantId, resultFromValidItem.tokenCacheStoreItem.profileInfo.tenantId);
    XCTAssertEqualObjects(item.profileInfo.username, resultFromValidItem.tokenCacheStoreItem.profileInfo.username);
    
    //Nil access token:
    item.accessToken = nil;
    ADAuthenticationResult* resultFromNilAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    VERIFY_ERROR_RESULT(resultFromNilAccessToken, AD_ERROR_UNEXPECTED);

    //Empty access token:
    item.accessToken = @"   ";
    ADAuthenticationResult* resultFromEmptyAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    VERIFY_ERROR_RESULT(resultFromEmptyAccessToken, AD_ERROR_UNEXPECTED);
}

@end
