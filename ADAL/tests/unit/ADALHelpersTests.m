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
#import "ADALHelpers.h"
#import "XCTestCase+TestHelperMethods.h"
#import "NSBundle+ADTestUtils.h"

@interface ADALHelpersTests : ADTestCase

@end

@implementation ADALHelpersTests

- (void)testAddClientVersion
{
    NSString* testURLString = @"https://test.microsoft.com/athing";

    NSDictionary *testMetadata = @{@"x-app-ver": @"1.0",
                                   @"x-app-name": @"UnitTestHostApp",
                                   @"x-client-Ver": @"Y"
                                   };

    NSString* result = [ADALHelpers addClientMetadataToURLString:testURLString metadata:testMetadata];
    XCTAssertEqualObjects(result, @"https://test.microsoft.com/athing?x-client-Ver=Y&x-app-ver=1.0&x-app-name=UnitTestHostApp");
}

- (void)testAddClientVersionPercentEncoded
{
    NSString* testURLString = @"https://test.microsoft.com/athing?dontunencodeme=this%3Dsome%26bsteststring%3Dtrue";
    NSString* result = [ADALHelpers addClientMetadataToURLString:testURLString metadata:@{@"x-app-ver": @"1.0",
                                                                                        @"x-app-name": @"UnitTestHostApp",
                                                                                        @"x-client-Ver": @"Y"
                                                                                        }];
    XCTAssertEqualObjects(result, @"https://test.microsoft.com/athing?dontunencodeme=this%3Dsome%26bsteststring%3Dtrue&x-client-Ver=Y&x-app-ver=1.0&x-app-name=UnitTestHostApp");
}

- (void)testAddClientVersionAlreadyThere
{
    NSString* testURLString = @"https://test.microsoft.com/athing?x-app-name=UnitTestHostApp&x-app-ver=1.0&x-client-Ver=Y";
    NSString* result = [ADALHelpers addClientMetadataToURLString:testURLString metadata:@{@"x-app-ver": @"1.0",
                                                                                        @"x-app-name": @"UnitTestHostApp",
                                                                                        @"x-client-Ver": @"Y"
                                                                                        }];
    XCTAssertEqualObjects(testURLString, result);
}

- (void)testCanonicalizeAuthority
{
    //Nil or empty:
    XCTAssertNil([ADALHelpers canonicalizeAuthority:nil]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@""]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"    "]);
    
    //Invalid URL
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"&-23425 5345g"]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"https:///login.windows.Net/something"], "Bad URL. Three slashes");
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"https:////"]);
    
    //Non-ssl:
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"something"]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"http://something"]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"http://www.microsoft.com"]);
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"abcde://login.windows.net/common"]);
    
    //Canonicalization to the supported extent:
    NSString* authority = @"    https://www.microsoft.com/something.com/";
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:authority], @"https://www.microsoft.com/something.com");
    
    authority = @"https://www.microsoft.com/something.com";
    //Without the trailing "/":
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://www.microsoft.com/something.com"], authority);
    //Ending with non-white characters:
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://www.microsoft.com/something.com   "], authority);
    
    authority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    //Test canonicalizing the endpoints:
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Token"], authority);
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Authorize"], authority);
    
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net"], "No tenant");
    XCTAssertNil([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/"], "No tenant");
    
    //Trimming beyond the tenant:
    authority = @"https://login.windows.net/something.com";
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com/bar"], authority);
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com"], authority);
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com/"], authority);
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com#bar"], authority);
    authority = @"https://login.windows.net/common";//Use "common" for a change
    ADAssertStringEquals([ADALHelpers canonicalizeAuthority:@"https://login.windows.net/common?abc=123&vc=3"], authority);
}


- (void)testGetSuffix
{
    //Nil or empty:
    XCTAssertNil([ADALHelpers getUPNSuffix:nil]);
    XCTAssertNil([ADALHelpers getUPNSuffix:@""]);
    XCTAssertNil([ADALHelpers getUPNSuffix:@"    "]);
    
    //Test right cases
    ADAssertStringEquals([ADALHelpers getUPNSuffix:@"user@microsoft.com"], @"microsoft.com");
}

@end
