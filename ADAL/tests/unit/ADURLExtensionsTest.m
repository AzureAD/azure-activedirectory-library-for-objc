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
#import "NSString+ADALURLExtensions.h"

@interface ADALURLExtensionsTest : XCTestCase

@end

@implementation ADALURLExtensionsTest

- (void)testAdAuthorityWithCloudInstanceName_whenNil_shouldReturnSame
{
    NSString *authority = @"https://login.microsoftonline.com/common";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:nil];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.com/common");
}

- (void)testAdAuthorityWithCloudInstanceName_whenEmpty_shouldReturnSame
{
    NSString *authority = @"https://login.microsoftonline.com/common";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"  "];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.com/common");
}

- (void)testAdAuthorityWithCloudInstanceName_whenCommon_shouldSwap
{
    NSString *authority = @"https://login.microsoftonline.com/common";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"login.microsoftonline.de"];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.de/common");
}

- (void)testAdAuthorityWithCloudInstanceName_whenWithTenant_shouldSwap
{
    NSString *authority = @"https://login.microsoftonline.com/b960c013-d381-403c-8d4d-939edac0d9ea";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"login.microsoftonline.de"];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.de/b960c013-d381-403c-8d4d-939edac0d9ea");
}

- (void)testAdAuthorityWithCloudInstanceName_whenLoginWindowsNet_shouldSwap
{
    NSString *authority = @"https://login.windows.net/common";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"login.microsoftonline.de"];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.de/common");
}

- (void)testAdAuthorityWithCloudInstanceName_whenLoginSts_shouldSwap
{
    NSString *authority = @"https://sts.microsoft.com/common";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"login.microsoftonline.de"];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://login.microsoftonline.de/common");
}

- (void)testAdAuthorityWithCloudInstanceName_whenNoHost_shouldReturnSame
{
    NSString *authority = @"https://";
    NSString *authorityWithCloudName = [authority adAuthorityWithCloudInstanceHostname:@"login.microsoftonline.de"];
    XCTAssertEqualObjects(authorityWithCloudName, @"https://");
}

@end
