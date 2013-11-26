//
//  ADUserInformationTests.m
//  ADALiOS
//
//  Created by Boris Vidolov on 11/14/13.
//  Copyright (c) 2013 MS Open Tech. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "XCTestCase+TestHelperMethods.h"
#import <ADALiOS/ADUserInformation.h>

@interface ADUserInformationTests : XCTestCase

@end

@implementation ADUserInformationTests

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

- (void) testCreator
{
    ADAuthenticationError* error;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithUserId:nil error:&error];
    [self validateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution
    userInfo = [ADUserInformation userInformationWithUserId:@"" error:&error];
    [self validateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution:
    userInfo = [ADUserInformation userInformationWithUserId:@"  " error:&error];
    [self validateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];
    
    error = nil;
    userInfo = [ADUserInformation userInformationWithUserId:@"valid user" error:&error];
    XCTAssertNotNil(userInfo);
    ADAssertNoError;
}

- (void) testCopy
{
    ADAuthenticationError* error;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithUserId:@"valid user" error:&error];
    ADAssertNoError;
    XCTAssertNotNil(userInfo);
    userInfo.givenName = @"given name  ";
    userInfo.familyName = @"  family name";
    userInfo.identityProvider = @" asdf afds";
    userInfo.userIdDisplayable = YES;//Non-default value
    
    ADUserInformation* copy = [userInfo copy];
    XCTAssertNotNil(copy);
    XCTAssertNotEqualObjects(copy, userInfo);
    ADAssertStringEquals(userInfo.userId, copy.userId);
    ADAssertStringEquals(userInfo.givenName, copy.givenName);
    ADAssertStringEquals(userInfo.familyName, copy.familyName);
    ADAssertStringEquals(userInfo.identityProvider, copy.identityProvider);
    XCTAssertEqual(userInfo.userIdDisplayable, copy.userIdDisplayable);
}

@end
