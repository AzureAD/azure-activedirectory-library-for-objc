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

#import "ADTestLoader.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"

@interface ADTestLoaderNetworkTests : XCTestCase

@end

#define ADTestGetOnlyRequest(_XML) \
    ADTestURLResponse *request = nil; \
    @try { request = ParseAndReturnOnlyRequest(_XML); } \
    @catch (NSException *ex) { XCTFail(@"%@", ex.reason); }

// This throws instead of using Asserts because that way we keep some semblance of locality on the test itself
// by using the XCTAssertNoThrow macro
static ADTestURLResponse *ParseAndReturnOnlyRequest(NSString * xml)
{
    NSError *error = nil;
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:xml];
    if (![loader parse:&error])
    {
        if (error.userInfo[@"exception"])
        {
            @throw error.userInfo[@"exception"];
        }
        @throw [NSException exceptionWithName:@"ParseFailed" reason:error.description userInfo:@{ @"error" : error }];
    }
    
    NSArray *requests = [loader networkRequests];
    if (!requests || requests.count == 0)
    {
        @throw [NSException exceptionWithName:@"ParseFailed" reason:@"No network requests returned" userInfo:nil];
    }
    
    if (requests.count > 1)
    {
        @throw [NSException exceptionWithName:@"ParseFailed" reason:@"Too many requests returned" userInfo:nil];
    }
    
    return requests[0];
}

@implementation ADTestLoaderNetworkTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testBasicRequestResponse_shouldPass
{
    ADTestGetOnlyRequest(@"<network><request url=\"https://login.contoso.com\" /><response code=\"200\"/></network>");
    XCTAssertEqualObjects(request->_requestURL, [NSURL URLWithString:@"https://login.contoso.com"]);
    XCTAssertEqual(((NSHTTPURLResponse *)request->_response).statusCode, 200);
}

- (void)testRequestHeaders_shouldPass
{
    ADTestGetOnlyRequest(@"<network>\n<request url=\"https://login.contoso.com\"><headers><WWW-Authenticate>token</WWW-Authenticate></headers></request>\n<response code=\"200\"/>\n</network>");
    XCTAssertEqualObjects(@{ @"www-authenticate" : @"token" }, request->_requestHeaders);
}

- (void)testRequestBody_shouldPass
{
    ADTestGetOnlyRequest(@"<network><request url=\"https://login.contoso.com\"><body>{\"param\" : \"value\"}</body></request><response code=\"200\" /></network>");
    
    XCTAssertEqualObjects(request->_requestBody, [@"{\"param\" : \"value\"}" dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testResponseBody_shouldPass
{
    ADTestGetOnlyRequest(@"<network><request url=\"https://login.contoso.com\"></request><response code=\"200\"><body>{\"param\" : \"value\"}</body></response></network>");
    
    XCTAssertEqualObjects(request->_responseData, [@"{\"param\" : \"value\"}" dataUsingEncoding:NSUTF8StringEncoding]);
}


@end
