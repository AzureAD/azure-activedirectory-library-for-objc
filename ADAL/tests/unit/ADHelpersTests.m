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
#import "ADHelpers.h"
#import "XCTestCase+TestHelperMethods.h"

@interface ADHelpersTests : XCTestCase

@end

@implementation ADHelpersTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testAddClientVersion
{
    NSString* testURLString = @"https://test.microsoft.com/athing";
    NSString* result = [ADHelpers addClientVersionToURLString:testURLString];
    XCTAssertEqualObjects(result, @"https://test.microsoft.com/athing?x-client-Ver=" ADAL_VERSION_STRING);
}

- (void)testAddClientVersionPercentEncoded
{
    NSString* testURLString = @"https://test.microsoft.com/athing?dontunencodeme=this%3Dsome%26bsteststring%3Dtrue";
    NSString* result = [ADHelpers addClientVersionToURLString:testURLString];
    XCTAssertEqualObjects(result, @"https://test.microsoft.com/athing?dontunencodeme=this%3Dsome%26bsteststring%3Dtrue&x-client-Ver=" ADAL_VERSION_STRING);
}

- (void)testAddClientVersionAlreadyThere
{
    NSString* testURLString = @"https://test.microsoft.com/athing?x-client-Ver=" ADAL_VERSION_STRING;
    NSString* result = [ADHelpers addClientVersionToURLString:testURLString];
    XCTAssertEqualObjects(testURLString, result);
}

- (void)testCanonicalizeAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    //Nil or empty:
    XCTAssertNil([ADHelpers canonicalizeAuthority:nil]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@""]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"    "]);
    
    //Invalid URL
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"&-23425 5345g"]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"https:///login.windows.Net/something"], "Bad URL. Three slashes");
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"https:////"]);
    
    //Non-ssl:
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"something"]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"http://something"]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"http://www.microsoft.com"]);
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"abcde://login.windows.net/common"]);
    
    //Canonicalization to the supported extent:
    NSString* authority = @"    https://www.microsoft.com/something.com/";
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:authority], @"https://www.microsoft.com/something.com");
    
    authority = @"https://www.microsoft.com/something.com";
    //Without the trailing "/":
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://www.microsoft.com/something.com"], authority);
    //Ending with non-white characters:
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://www.microsoft.com/something.com   "], authority);
    
    authority = @"https://login.windows.net/msopentechbv.onmicrosoft.com";
    //Test canonicalizing the endpoints:
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Token"], authority);
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/MSOpenTechBV.onmicrosoft.com/OAuth2/Authorize"], authority);
    
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"https://login.windows.Net"], "No tenant");
    XCTAssertNil([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/"], "No tenant");
    
    //Trimming beyond the tenant:
    authority = @"https://login.windows.net/something.com";
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com/bar"], authority);
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com"], authority);
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com/"], authority);
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.Net/something.com#bar"], authority);
    authority = @"https://login.windows.net/common";//Use "common" for a change
    ADAssertStringEquals([ADHelpers canonicalizeAuthority:@"https://login.windows.net/common?abc=123&vc=3"], authority);
}


- (void)testGetSuffix
{
    //Nil or empty:
    XCTAssertNil([ADHelpers getUPNSuffix:nil]);
    XCTAssertNil([ADHelpers getUPNSuffix:@""]);
    XCTAssertNil([ADHelpers getUPNSuffix:@"    "]);
    
    //Test right cases
    ADAssertStringEquals([ADHelpers getUPNSuffix:@"user@microsoft.com"], @"microsoft.com");
}

@end
