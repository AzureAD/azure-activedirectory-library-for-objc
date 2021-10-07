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

#import "ADALAuthenticationContextTests.h"
#import "ADALAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADALErrorCodes.h"
#import "ADALTokenCache+Internal.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALUserIdentifier.h"
#import "ADALAuthenticationRequest.h"

@interface ADALAuthenticationContextTests (iOS)

@end

@implementation ADALAuthenticationContextTests (iOS)

#pragma mark - authenticationContextWithAuthority

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADALAuthenticationContext authenticationContextWithAuthority:authority sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilValidateAuthorityNoSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADALAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:@"   " sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankValidateAuthorityNoSharedGroupNil_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidSharedGroupNil_shouldReturnContextAndNilError
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY sharedGroup:nil error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidValidateAuthorityNoShareGroupNil_shouldReturnContextAndNilError
{
    ADALAuthenticationContext* context = nil;
    ADALAuthenticationError* error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO sharedGroup:nil error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

@end
