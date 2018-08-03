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
#import "ADUserInformation.h"

@interface ADUserInformationTests : ADTestCase

@end

@implementation ADUserInformationTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - isEqual

- (void)testIsEqual_whenAllPropertiesAreEqual_shouldReturnTrue
{
    ADUserInformation *lhs = [self adCreateUserInformation:@"eric_cartman@contoso.com" homeAccountId:@"123"];
    ADUserInformation *rhs = [self adCreateUserInformation:@"eric_cartman@contoso.com" homeAccountId:@"123"];
    
    XCTAssertEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenRawIdTokenIsNotEqual_shouldReturnFalse
{
    ADUserInformation *lhs = [self createEmptyUserInformation];
    [lhs setValue:@"asd" forKey:@"rawIdToken"];
    ADUserInformation *rhs = [self createEmptyUserInformation];
    [rhs setValue:@"qwe" forKey:@"rawIdToken"];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

- (void)testIsEqual_whenHomeAccountIdIsNotEqual_shouldReturnFalse
{
    ADUserInformation *lhs = [self createEmptyUserInformation];
    [lhs setValue:@"qwe" forKey:@"homeAccountId"];
    ADUserInformation *rhs = [self createEmptyUserInformation];
    [rhs setValue:@"asd" forKey:@"homeAccountId"];
    
    XCTAssertNotEqualObjects(lhs, rhs);
}

#pragma mark - userInformationWithIdToken

- (void)testUserInformationWithIdToken_whenUpnContainsSpaces_shouldReturnTrimmedUserId
{
    NSDictionary *part1Claims = @{ @"typ" : @"JWT", @"alg" : @"none" };
    NSString *p1 = [NSString msidBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:part1Claims options:0 error:nil]];
    NSDictionary *idtokenClaims = @{@"upn" : @"     eric_cartman@contoso.com           ", @"ver": @"1.0"};
    NSString *p2 = [NSString msidBase64UrlEncodeData:[NSJSONSerialization dataWithJSONObject:idtokenClaims options:0 error:nil]];
    NSString *idtoken = [NSString stringWithFormat:@"%@.%@.", p1, p2];
    
    ADUserInformation *userInfo = [ADUserInformation userInformationWithIdToken:idtoken
                                                                          error:nil];
    
    ADAssertStringEquals(userInfo.userId, @"eric_cartman@contoso.com");
}

#pragma mark - copyWithZone

- (void)testCopyWithZone_whenAllPropertiesAreSet_shouldCopyAllOfThem
{
    ADUserInformation *userInfo = [self adCreateUserInformation:@"eric_cartman@contoso.com"];
    
    ADUserInformation *userInfoCopy = [userInfo copy];
    
    XCTAssertEqualObjects(userInfo.rawIdToken, userInfoCopy.rawIdToken);
    XCTAssertEqualObjects(userInfo.userId, userInfoCopy.userId);
    XCTAssertEqual(userInfo.userIdDisplayable, userInfoCopy.userIdDisplayable);
    XCTAssertEqualObjects(userInfo.uniqueId, userInfoCopy.uniqueId);
    XCTAssertEqualObjects(userInfo.allClaims, userInfoCopy.allClaims);
    XCTAssertEqualObjects(userInfo, userInfoCopy);
}

#pragma mark -

- (void) testIdTokenNormal
{
    NSString* normalToken = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9.";
    ADAuthenticationError* error = nil;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:normalToken
                                                                          error:&error];
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
    ADAuthenticationError* error = nil;
    ADUserInformation* userInfo = [ADUserInformation userInformationWithIdToken:@""
                                                                          error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADUserInformation userInformationWithIdToken:nil
                                                       error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    userInfo = [ADUserInformation userInformationWithIdToken:@"....."
                                                       error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    //Skip the header. Ensure that the method recovers and still reads the contents:
    error = nil;//Reset it, as it was set in the previous calls
    NSString* missingHeader = @"eyJhdWQiOiJjM2M3ZjVlNS03MTUzLTQ0ZDQtOTBlNi0zMjk2ODZkNDhkNzYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ZmQxZjVjZC1hOTRjLTQzMzUtODg5Yi02YzU5OGU2ZDgwNDgvIiwiaWF0IjoxMzg3MjI0MTY5LCJuYmYiOjEzODcyMjQxNjksImV4cCI6MTM4NzIyNzc2OSwidmVyIjoiMS4wIiwidGlkIjoiNmZkMWY1Y2QtYTk0Yy00MzM1LTg4OWItNmM1OThlNmQ4MDQ4Iiwib2lkIjoiNTNjNmFjZjItMjc0Mi00NTM4LTkxOGQtZTc4MjU3ZWM4NTE2IiwidXBuIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoiYm9yaXNATVNPcGVuVGVjaEJWLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjBEeG5BbExpMTJJdkdMX2RHM2RETWszenA2QVFIbmpnb2d5aW01QVdwU2MiLCJmYW1pbHlfbmFtZSI6IlZpZG9sb3Z2IiwiZ2l2ZW5fbmFtZSI6IkJvcmlzcyJ9";
    userInfo = [ADUserInformation userInformationWithIdToken:missingHeader
                                                       error:&error];
    ADAssertNoError;
    ADAssertStringEquals(userInfo.userId.lowercaseString, @"boris@msopentechbv.onmicrosoft.com");
    ADAssertStringEquals(userInfo.familyName, @"Vidolovv");
    ADAssertStringEquals(userInfo.givenName, @"Boriss");

    
    //Pass nil for error:
    userInfo = [ADUserInformation userInformationWithIdToken:@"....."
                                                       error:nil];
    XCTAssertNil(userInfo);

    error = nil;
    NSString* plain = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";
    userInfo = [ADUserInformation userInformationWithIdToken:plain
                                                       error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    error = nil;
    NSString* plainNoUserId = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"}";//Missing meaningful userID field
    NSString* encoded = [plainNoUserId msidBase64UrlEncode];
    userInfo = [ADUserInformation userInformationWithIdToken:encoded
                                                       error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
    
    
    error = nil;
    NSString* badJSON = @"{\"aud\":\"c3c7f5e5-7153-44d4-90e6-329686d48d76\",\"iss\":\"https://sts.windows.net/6fd1f5cd-a94c-4335-889b-6c598e6d8048/\",\"iat\":1387224169,\"nbf\":1387224169,\"exp\":1387227769,\"ver\":\"1.0\",\"tid\":\"6fd1f5cd-a94c-4335-889b-6c598e6d8048\",\"oid\":\"53c6acf2-2742-4538-918d-e78257ec8516\",\"upn\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"unique_name\":\"boris@MSOpenTechBV.onmicrosoft.com\",\"sub\":\"0DxnAlLi12IvGL_dG3dDMk3zp6AQHnjgogyim5AWpSc\",\"family_name\":\"Vidolovv\",\"given_name\":\"Boriss\"";//Missing closing braket '}'
    encoded = [badJSON msidBase64UrlEncode];
    userInfo = [ADUserInformation userInformationWithIdToken:encoded
                                                       error:&error];
    XCTAssertNotNil(error);
    XCTAssertNil(userInfo);
}

-(void) testSupportSecureCoding
{
    XCTAssertTrue([ADUserInformation supportsSecureCoding], "Unarchiving should be secure.");
}

- (ADUserInformation *)createEmptyUserInformation
{
    ADUserInformation *information = [self adCreateUserInformation:@"eric_cartman@contoso.com" homeAccountId:@"1234.home"];
    [information setValue:nil forKey:@"allClaims"];
    [information setValue:nil forKey:@"rawIdToken"];
    [information setValue:nil forKey:@"uniqueId"];
    [information setValue:@NO forKey:@"userIdDisplayable"];
    [information setValue:nil forKey:@"userId"];
    
    return information;
}

@end
