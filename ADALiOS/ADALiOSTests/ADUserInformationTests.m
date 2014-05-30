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
#import <ADALiOS/ADUserInformation.h>

@interface ADUserInformationTests : XCTestCase

@end

@implementation ADUserInformationTests

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

- (void) testCreator
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationError* error;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithUserId:nil error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution
    userInfo = [ADUserInformation userInformationWithUserId:@"" error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    error = nil;//Clear before next execution:
    userInfo = [ADUserInformation userInformationWithUserId:@"  " error:&error];
    [self adValidateFactoryForInvalidArgument:@"userId" returnedObject:userInfo error:error];

    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    error = nil;
    userInfo = [ADUserInformation userInformationWithUserId:@"valid user" error:&error];
    XCTAssertNotNil(userInfo);
    ADAssertNoError;
}

- (void) testCopy
{
    ADUserInformation* userInfo = [self adCreateUserInformation];
    XCTAssertNotNil(userInfo);
    
    ADUserInformation* copy = [userInfo copy];
    XCTAssertNotNil(copy);
    XCTAssertNotEqualObjects(copy, userInfo);
    ADAssertStringEquals(userInfo.userId, copy.userId);
    ADAssertStringEquals(userInfo.givenName, copy.givenName);
    ADAssertStringEquals(userInfo.familyName, copy.familyName);
    ADAssertStringEquals(userInfo.identityProvider, copy.identityProvider);
    XCTAssertEqual(userInfo.userIdDisplayable, copy.userIdDisplayable);
    XCTAssertEqual(userInfo.allClaims, copy.allClaims);
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
    ADAssertStringEquals(userInfo.rawIdToken, normalToken);
    //Test one random property:
    ADAssertStringEquals([userInfo.allClaims objectForKey:@"given_name"], userInfo.givenName);
}

-(void) testIdTokenBad
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADAuthenticationError* error = nil;
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
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_WARN];
    //Skip the header. Ensure that the method recovers and still reads the contents:
    error = nil;//Reset it, as it was set in the previous calls
    NSString* missingHeader = @"eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9";
    userInfo = [ADUserInformation userInformationWithIdToken:missingHeader error:&error];
    ADAssertNoError;
    ADAssertStringEquals(userInfo.userId.lowercaseString, @"boris@msopentechbv.onmicrosoft.com");
    ADAssertStringEquals(userInfo.familyName, @"Vidolovv");
    ADAssertStringEquals(userInfo.givenName, @"Boriss");

    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Pass nil for error:
    userInfo = [ADUserInformation userInformationWithIdToken:@"....." error:nil];
    XCTAssertNil(userInfo);

    error = nil;
    NSString* plain = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";
    userInfo = [ADUserInformation userInformationWithIdToken:plain error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    NSString* plainNoUserId = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";//Missing meaningful userID field
    NSString* encoded = [plainNoUserId adBase64UrlEncode];
    userInfo = [ADUserInformation userInformationWithIdToken:encoded error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    
    error = nil;
    NSString* badJSON = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"";//Missing closing braket '}'
    encoded = [badJSON adBase64UrlEncode];
    userInfo = [ADUserInformation userInformationWithIdToken:encoded error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
}

-(void) testSupportSecureCoding
{
    XCTAssertTrue([ADUserInformation supportsSecureCoding], "Unarchiving should be secure.");
}

@end
