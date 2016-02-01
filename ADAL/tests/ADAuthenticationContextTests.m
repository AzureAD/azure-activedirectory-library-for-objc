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
#import "ADAuthenticationContext.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADErrorCodes.h"

#define TEST_AUTHORITY @"https://login.windows.net/contoso.com"

@interface ADAuthenticationContextTests : XCTestCase

@end

@implementation ADAuthenticationContextTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testNew
{
    XCTAssertThrows([ADAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit
{
    XCTAssertThrows([[ADAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testNilAuthority
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil sharedGroup:nil error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
#endif // TARGET_OS_IPHONE
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:nil validateAuthority:NO sharedGroup:nil error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
#endif
}

- (void)testBlankAuthority
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " sharedGroup:nil error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
#endif // TARGET_OS_IPHONE
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO sharedGroup:nil error:&error];
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    error = nil;
#endif // TARGET_OS_IPHONE
}

- (void)testValidAuthority
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY error:&error];
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY sharedGroup:nil error:&error];
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
#endif // TARGET_OS_IPHONE
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO error:&error];
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    
#if TARGET_OS_IPHONE
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO sharedGroup:nil error:&error];
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
#endif // TARGET_OS_IPHONE
}

@end
