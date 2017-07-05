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

@interface ADAuthenticationErrorTests : XCTestCase

@end

@implementation ADAuthenticationErrorTests

- (void)setUp
{
    [super setUp];
    
    // Put setup code here; it will be run once, before the first test case.
    [self adTestBegin:ADAL_LOG_LEVEL_ERROR];
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [self adTestEnd];
    
    [super tearDown];
}

- (void)testNew
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_INFO];
    XCTAssertThrows([ADAuthenticationError new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit
{
    XCTAssertThrows([ADAuthenticationError init], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParentInitWithDomain
{
    XCTAssertThrows([[ADAuthenticationError alloc] initWithDomain:@"domain" code:123 userInfo:nil], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testErrorFromArgumentNameNil
{
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:@"val" argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:@"" argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
    XCTAssertThrowsSpecificNamed([ADAuthenticationError errorFromArgument:nil argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
}

- (void)testErrorFromArgumentNil
{
    NSString* parameter = @"parameter123456 %@";
    //nil value:
    ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:nil argumentName:parameter correlationId:nil];
    XCTAssertNotNil(error, "No error for nil prameter");
    [self adValidateForInvalidArgument:parameter error:error];
    XCTAssertTrue([error.errorDetails containsString:@"(null)"], "'null' should be part of the text");
}

- (void)testErrorFromArgumentNormal
{
    NSString* parameter = @"parameter123456 %@";
    NSString* parameterValue = @"value1245 %s@";
    ADAuthenticationError* error = [ADAuthenticationError errorFromArgument:parameterValue argumentName:parameter correlationId:nil];
    XCTAssertNotNil(error, "No error for valid prameter");
    
    [self adValidateForInvalidArgument:parameter error:error];
    XCTAssertTrue([error.errorDetails containsString:parameterValue], "Value should be part of the text");
}

- (void)testErrorFromOAuthError
{
    NSString* details = @"Some details";
    NSString* protocolCode = @"procol code";
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_OAUTH protocolCode:protocolCode errorDetails:details correlationId:nil];
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    ADAssertLongEquals(error.code, AD_ERROR_SERVER_OAUTH);
    ADAssertStringEquals(error.protocolCode, protocolCode);
    ADAssertStringEquals(error.errorDetails, details);
}

- (void)testDescription
{
    NSString* details = @"Some details";
    NSString* protocolCode = @"some-protocol-code";
    ADAuthenticationError* error = [ADAuthenticationError errorFromAuthenticationError:42 protocolCode:protocolCode errorDetails:details correlationId:nil];
    XCTAssertTrue([error.description containsString:details]);
    XCTAssertTrue([error.description containsString:protocolCode]);
}

@end
