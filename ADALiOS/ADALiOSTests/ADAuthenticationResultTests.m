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

@interface ADAuthenticationResultTests : XCTestCase

@end

@implementation ADAuthenticationResultTests

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

//Only static creators and internal initializers are supported. init and new should throw.
- (void) testInitAndNew
{
    XCTAssertThrows([[ADAuthenticationResult alloc] init]);
    XCTAssertThrows([ADAuthenticationResult new]);
}

-(void) verifyErrorResult: (ADAuthenticationResult*) result
                errorCode: (ADErrorCode) code
{
    XCTAssertNotNil(result);
    ADAuthenticationResultStatus expected = (code == AD_ERROR_USER_CANCEL) ? AD_USER_CANCELLED : AD_FAILED;
    XCTAssertEqual(result.status, expected, "Wrong status on cancellation");
    XCTAssertNotNil(result.error, "Nil error");
    ADAssertLongEquals(result.error.code, code);
    XCTAssertNil(result.tokenCacheStoreItem.accessToken);
    XCTAssertNil(result.tokenCacheStoreItem.accessTokenType);
    XCTAssertNil(result.tokenCacheStoreItem.refreshToken);
    XCTAssertNil(result.tokenCacheStoreItem.expiresOn);
    XCTAssertNil(result.tokenCacheStoreItem.userInformation);
}

-(void) testResultFromCancellation
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromCancellation];
    [self verifyErrorResult:result errorCode:AD_ERROR_USER_CANCEL];
}

-(void) testResultFromError
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationError* error = [ADAuthenticationError unexpectedInternalError:@"something"];
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromError:error];
    [self verifyErrorResult:result errorCode:AD_ERROR_UNEXPECTED];
    XCTAssertEqualObjects(result.error, error, "Different error object in the result.");
}

-(void) verifyResult: (ADAuthenticationResult*) resultFromItem
                item: (ADTokenCacheStoreItem*) item
{
    XCTAssertNotNil(resultFromItem);
    XCTAssertEqual(resultFromItem.status, AD_SUCCEEDED, "Result should be success.");
    XCTAssertNil(resultFromItem.error, "Unexpected error object: %@", resultFromItem.error.errorDetails);
    XCTAssertEqual(item.accessTokenType, resultFromItem.tokenCacheStoreItem.accessTokenType);
    XCTAssertEqual(item.accessToken, resultFromItem.tokenCacheStoreItem.accessToken);
    XCTAssertEqual(item.expiresOn, resultFromItem.tokenCacheStoreItem.expiresOn);
    XCTAssertEqual(item.userInformation.tenantId, resultFromItem.tokenCacheStoreItem.userInformation.tenantId);
    ADAssertStringEquals(item.userInformation.userId, resultFromItem.tokenCacheStoreItem.userInformation.userId);
}

-(void) testResultFromTokenCacheStoreItem
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationResult* nilItemResult = [ADAuthenticationResult resultFromTokenCacheStoreItem:nil multiResourceRefreshToken:NO];
    [self verifyErrorResult:nilItemResult errorCode:AD_ERROR_UNEXPECTED];
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net/mytennant.com";
    item.clientId = @"clientId";
    item.accessToken = @"accessToken";
    item.accessTokenType = @"tokenType";
    item.refreshToken = @"refreshToken";
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:@"user" error:&error];
    ADAssertNoError;
    
    //Copy the item to ensure that it is not modified withing the method call below:
    ADAuthenticationResult* resultFromValidItem = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy] multiResourceRefreshToken:NO];
    [self verifyResult:resultFromValidItem item:item];
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Nil access token:
    item.resource = @"resource";//Restore
    item.accessToken = nil;
    ADAuthenticationResult* resultFromNilAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy] multiResourceRefreshToken:NO];
    [self verifyErrorResult:resultFromNilAccessToken errorCode:AD_ERROR_UNEXPECTED];

    //Empty access token:
    item.resource = @"resource";//Restore
    item.accessToken = @"   ";
    ADAuthenticationResult* resultFromEmptyAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy] multiResourceRefreshToken:NO];
    [self verifyErrorResult:resultFromEmptyAccessToken errorCode:AD_ERROR_UNEXPECTED];
}

@end
