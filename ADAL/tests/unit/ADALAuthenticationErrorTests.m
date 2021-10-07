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

@interface ADALAuthenticationErrorTests : ADTestCase

@end

@implementation ADALAuthenticationErrorTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - Initialization

- (void)testNew_shouldThrow
{
    XCTAssertThrows([ADALAuthenticationError new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit_shouldThrow
{
    XCTAssertThrows([[ADALAuthenticationError alloc] init], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParentInitWithDomain_shouldThrow
{
    XCTAssertThrows([[ADALAuthenticationError alloc] initWithDomain:@"domain" code:123 userInfo:nil], @"Parameterless init should throw. At: '%s'", __PRETTY_FUNCTION__);
}

#pragma mark - errorFromArgument

- (void)testErrorFromArgument_whenArgumentIsValidArgumentNameNilCorrelationIdNil_shouldThrow
{
    XCTAssertThrowsSpecificNamed([ADALAuthenticationError errorFromArgument:@"val" argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
}

- (void)testErrorFromArgument_whenArgumentIsEmptyStringArgumentNameNilCorrelationIdNil_shouldThrow
{
    XCTAssertThrowsSpecificNamed([ADALAuthenticationError errorFromArgument:@"" argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
}

- (void)testErrorFromArgument_whenArgumentNilArgumentNameNilCorrelationIdNil_shouldThrow
{
    XCTAssertThrowsSpecificNamed([ADALAuthenticationError errorFromArgument:nil argumentName:nil correlationId:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
}

- (void)testErrorFromArgument_whenArgumentNilArgumentNameIsValidCorrelationIdNil_shouldReturnError
{
    NSString *parameter = @"parameter123456 %@";
    
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromArgument:nil argumentName:parameter correlationId:nil];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The argument 'parameter123456 %@' is invalid. Value:(null)");
}

- (void)testErrorFromArgument_whenArgumentIsValidArgumentNameIsValidCorrelationIdNil_shouldReturnError
{
    NSString *parameter = @"parameter123456 %@";
    NSString *parameterValue = @"value1245 %s@";
    
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromArgument:parameterValue argumentName:parameter correlationId:nil];
    
    XCTAssertNotNil(error);
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    XCTAssertNil(error.protocolCode);
    ADAssertStringEquals(error.errorDetails, @"The argument 'parameter123456 %@' is invalid. Value:value1245 %s@");
}

#pragma mark - errorFromAuthenticationError

- (void)testErrorFromAuthenticationError_whenCodeValidErrorProtocolValidDetailsValidCorrelationIdNil_shouldReturnError
{
    NSString *details = @"Some details";
    NSString *protocolCode = @"procol code";
    
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromAuthenticationError:AD_ERROR_SERVER_OAUTH protocolCode:protocolCode errorDetails:details correlationId:nil];
    
    ADAssertStringEquals(error.domain, ADAuthenticationErrorDomain);
    ADAssertLongEquals(error.code, AD_ERROR_SERVER_OAUTH);
    ADAssertStringEquals(error.protocolCode, protocolCode);
    ADAssertStringEquals(error.errorDetails, details);
}

- (void)testErrorFromAuthenticationError_whenErrorValidCodeValidErrorDetailsValidCorrelationIdNil_shouldReturnErrorWithDescription
{
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromAuthenticationError:42 protocolCode:@"some-protocol-code" errorDetails:@"Some details" correlationId:nil];
    
    ADAssertStringEquals(error.description, @"Error with code: 42 Domain: ADAuthenticationErrorDomain ProtocolCode:some-protocol-code Details:Some details. Inner error details: Error Domain=ADAuthenticationErrorDomain Code=42 \"(null)\"");
}

#pragma mark - HTTP headers

- (void)testErrorFromHTTPError_whenCodeValidBodyValidHeadersNil_shouldReturnErrorWithEmptyUserInfo
{
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromHTTPErrorCode:429 body:@"test_body" headers:nil correlationId:nil];
    XCTAssertEqual([error.userInfo count], 0);
}

- (void)testErrorFromHTTPError_whenCodeValidBodyValidHeaderPresent_shouldReturnErrorWithUserInfoAndHeaders
{
    NSDictionary *headers = @{@"Connection":@"Keep-Alive",
                              @"Retry-After": @120};
    
    ADALAuthenticationError *error = [ADALAuthenticationError errorFromHTTPErrorCode:429 body:@"test_body" headers:headers correlationId:nil];
    XCTAssertNotNil(error.userInfo);
    
    NSDictionary *headersDictionary = error.userInfo[ADHTTPHeadersKey];
    XCTAssertNotNil(headersDictionary);
    XCTAssertEqualObjects(headersDictionary[@"Retry-After"], @120);
    XCTAssertEqualObjects(headersDictionary[@"Connection"], @"Keep-Alive");
}

@end
