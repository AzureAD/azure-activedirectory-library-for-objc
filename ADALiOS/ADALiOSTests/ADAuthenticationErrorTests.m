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

@interface ADAuthenticationErrorTests : XCTestCase

@end

@implementation ADAuthenticationErrorTests

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

- (void)testNew
{
    XCTAssertThrows([ADAuthenticationError new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

-(void)testParameterlessInit
{
    XCTAssertThrows([ADAuthenticationError init], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

-(void)testParentInitWithDomain
{
    XCTAssertThrows([[ADAuthenticationError alloc] initWithDomain:@"domain" code:123 userInfo:nil], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

-(void)testErrorFromArgumentNameNil
{
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:@"val" argumentName:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:@"" argumentName:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:nil argumentName:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
}

-(void)testErrorFromArgumentNil
{
    NSString* parameter = @"parameter123456 %@";
    //nil value:
    ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:nil argumentName:parameter];
    XCTAssertNotNil(error, "No error for nil prameter");
    ADAssertArgumentError(parameter, error);
    XCTAssertTrue([error.errorDetails adContainsString:@"(null)"], "'null' should be part of the text");
}

-(void) testErrorFromArgumentNormal
{
    NSString* parameter = @"parameter123456 %@";
    NSString* parameterValue = @"value1245 %s@";
    ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:parameterValue argumentName:parameter];
    XCTAssertNotNil(error, "No error for valid prameter");
    
    ADAssertArgumentError(parameter, error);
    XCTAssertTrue([error.errorDetails adContainsString:parameterValue], "Value should be part of the text");
}

-(void)testErrorFromUnauthorizedResponseNormal
{
    NSString* details = @"Some details";
    ADAuthenticationError* error = [ADAuthenticationError errorFromUnauthorizedResponse:AD_ERROR_MISSING_AUTHENTICATE_HEADER errorDetails:details];
    XCTAssertNotNil(error, "Nil returned for valid case");
}

-(void) testErrorFromOAuthError
{
    NSString* details = @"Some details";
    NSString* protocolCode = @"procol code";
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_AUTHENTICATION protocolCode:protocolCode errorDetails:details];
    XCTAssertEqualObjects(error.domain, ADAuthenticationErrorDomain);
    ADAssertLongEquals(error.code, AD_ERROR_AUTHENTICATION);
    XCTAssertEqualObjects(error.protocolCode, protocolCode);
    XCTAssertEqualObjects(error.errorDetails, details);
}

-(void) testDescription
{
    NSString* details = @"Some details";
    NSString* protocolCode = @"some-protocol-code";
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:42 protocolCode:protocolCode errorDetails:details];
    XCTAssertTrue([error.description adContainsString:details]);
    XCTAssertTrue([error.description adContainsString:protocolCode]);
}

@end
