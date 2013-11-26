//
//  ADAuthenticationResultTests.m
//  ADALiOS
//
//  Created by Boris Vidolov on 11/13/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "ADAuthenticationResult+Internal.h"
#import <ADALiOS/ADTokenCacheStoreItem.h>
#import "XCTestCase+TestHelperMethods.h"

@interface ADAuthenticationResultTests : XCTestCase

@end

@implementation ADAuthenticationResultTests

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
    XCTAssertEqual(result.error.code, code, "Wrong error code");
    XCTAssertNil(result.accessToken);
    XCTAssertNil(result.accessTokenType);
    XCTAssertNil(result.refreshToken);
    XCTAssertNil(result.expiresOn);
    XCTAssertNil(result.tenantId);
    XCTAssertNil(result.userInformation);
}

-(void) testResultFromCancellation
{
    ADAuthenticationResult* result = [ADAuthenticationResult resultFromCancellation];
    [self verifyErrorResult:result errorCode:AD_ERROR_USER_CANCEL];
}

-(void) testResultFromError
{
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
    XCTAssertEqual(item.accessTokenType, resultFromItem.accessTokenType);
    XCTAssertEqual(item.accessToken, resultFromItem.accessToken);
    XCTAssertEqual(item.expiresOn, resultFromItem.expiresOn);
    XCTAssertEqual(item.tenantId, resultFromItem.tenantId);
    ADAssertStringEquals(item.userInformation.userId, resultFromItem.userInformation.userId);
}

-(void) testResultFromTokenCacheStoreItem
{
    ADAuthenticationResult* nilItemResult = [ADAuthenticationResult resultFromTokenCacheStoreItem:nil];
    [self verifyErrorResult:nilItemResult errorCode:AD_ERROR_UNEXPECTED];
    
    ADTokenCacheStoreItem* item = [[ADTokenCacheStoreItem alloc] init];
    item.resource = @"resource";
    item.authority = @"https://login.windows.net";
    item.clientId = @"clientId";
    item.accessToken = @"accessToken";
    item.accessTokenType = @"tokenType";
    item.refreshToken = @"refreshToken";
    item.expiresOn = [NSDate dateWithTimeIntervalSinceNow:30];
    ADAuthenticationError* error;
    item.userInformation = [ADUserInformation userInformationWithUserId:@"user" error:&error];
    ADAssertNoError;
    item.tenantId = @"tenantId";
    
    //Copy the item to ensure that it is not modified withing the method call below:
    ADAuthenticationResult* resultFromValidItem = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    [self verifyResult:resultFromValidItem item:item];
    
    //Turn into bad item:
    item.resource = nil;
    ADAuthenticationResult* resultFromBadKeyItem = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    [self verifyErrorResult:resultFromBadKeyItem errorCode:AD_ERROR_INVALID_ARGUMENT];
    
    //Nil access token:
    item.resource = @"resource";//Restore
    item.accessToken = nil;
    ADAuthenticationResult* resultFromNilAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    [self verifyErrorResult:resultFromNilAccessToken errorCode:AD_ERROR_UNEXPECTED];

    //Empty access token:
    item.resource = @"resource";//Restore
    item.accessToken = @"   ";
    ADAuthenticationResult* resultFromEmptyAccessToken = [ADAuthenticationResult resultFromTokenCacheStoreItem:[item copy]];
    [self verifyErrorResult:resultFromEmptyAccessToken errorCode:AD_ERROR_UNEXPECTED];
}

@end
