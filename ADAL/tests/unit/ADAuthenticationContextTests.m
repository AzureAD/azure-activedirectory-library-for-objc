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

#import "ADAuthenticationContextTests.h"
#import "ADAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADErrorCodes.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem+Internal.h"
#import "ADUserIdentifier.h"
#import "ADAuthenticationRequest.h"

@implementation ADAuthenticationContextTests

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
    XCTAssertThrows([ADAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit_shouldThrow
{
    XCTAssertThrows([[ADAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

#pragma mark - authenticationContextWithAuthority

- (void)testAuthenticationContextWithAuthority_whenAuthorityNil_shouldReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNil_shouldReturnNilContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil error:&error];
    
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilValidatedAuthorityNo_shouldReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilValidatedAuthorityNo_shouldReturnNilContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO error:&error];
    
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlank_shouldReturnNilContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " error:&error];
    
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlank_shouldReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankValidateAuthorityNo_shouldReturnNilContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO error:&error];
    
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankValidateAuthorityNo_shouldReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValid_shouldReturnContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValid_shouldNotReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY error:&error];
    
    XCTAssertNil(error);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidValidateAuthorityNo_shouldReturnContext
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidValidateAuthorityNo_shouldNotReturnError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO error:&error];
    
    XCTAssertNil(error);
}

@end
