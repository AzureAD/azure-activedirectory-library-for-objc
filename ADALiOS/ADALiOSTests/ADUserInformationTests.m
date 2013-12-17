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

- (void) testIdTokenNormal
{
    NSString* normalToken = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9.";
    ADAuthenticationError* error;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:normalToken error:&error];
    ADAssertNoError;
    ADAssertStringEquals(userInfo.userId.lowercaseString, @"boris@msopentechbv.onmicrosoft.com");
    ADAssertStringEquals(userInfo.familyName, @"Vidolovv");
    ADAssertStringEquals(userInfo.givenName, @"Boriss");
}

-(void) testIdTokenBad
{
    ADAuthenticationError* error;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:@"" error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADUserInformation userInformationWithIdToken:nil error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADUserInformation userInformationWithIdToken:@"....." error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    //Skip the header. Ensure that the method recovers and still reads the contents:
    error = nil;//Reset it, as it was set in the previous calls
    NSString* missingHeader = @"eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9";
    userInfo = [ADUserInformation userInformationWithIdToken:missingHeader error:&error];
    ADAssertNoError;
    ADAssertStringEquals(userInfo.userId.lowercaseString, @"boris@msopentechbv.onmicrosoft.com");
    ADAssertStringEquals(userInfo.familyName, @"Vidolovv");
    ADAssertStringEquals(userInfo.givenName, @"Boriss");
    
    //Pass nil for error:
    userInfo = [ADUserInformation userInformationWithIdToken:@"....." error:nil];
    XCTAssertNil(userInfo);
    
    error = nil;
    NSString* plain = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";
    userInfo = [ADUserInformation userInformationWithIdToken:plain error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    NSString* plainNoUserId = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";
    NSString* encoded = [plainNoUserId adBase64UrlEncode];
    userInfo = [ADUserInformation userInformationWithIdToken:encoded error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
}

@end
