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

@interface ADAuthenticationContextTests (iOS)

@end

@implementation ADAuthenticationContextTests (iOS)

#pragma mark - authenticationContextWithAuthority

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADAuthenticationContext *context = nil;
    ADAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADAuthenticationContext authenticationContextWithAuthority:authority sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilValidateAuthorityNoSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADAuthenticationContext *context = nil;
    ADAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADAuthenticationContext *context = nil;
    ADAuthenticationError *error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankValidateAuthorityNoSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADAuthenticationContext *context = nil;
    ADAuthenticationError *error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidSharedGroupNil_shouldReturnContextAndNilError
{
    ADAuthenticationContext *context = nil;
    ADAuthenticationError *error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY sharedGroup:nil error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidValidateAuthorityNoShareGroupNil_shouldReturnContextAndNilError
{
    ADAuthenticationContext* context = nil;
    ADAuthenticationError* error = nil;
    
    context = [ADAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

@end
