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
#import "NSURL+ADExtensions.h"
#import "XCTestCase+TestHelperMethods.h"

@interface NSURLExtensionsTests : XCTestCase

@end

@implementation NSURLExtensionsTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//tests the fragment extraction. Does not test any other URL logic,
//which should have been handled by the NSURL class
- (void)testFragmentParameters
{
    //Missing or invalid fragment:
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com"]).adFragmentParameters);
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar"]).adFragmentParameters);
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com#bar=foo#"]).adFragmentParameters);
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#bar=foo#foo=bar"]).adFragmentParameters);
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#bar=foo#foo=bar#"]).adFragmentParameters);
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#        "]).adFragmentParameters);
    
    //Valid fragment, but missing/invalid parameters:
    NSDictionary* empty = [NSDictionary new];
    XCTAssertEqualObjects(empty, ((NSURL*)[NSURL URLWithString:@"https://stuff.com#bar"]).adFragmentParameters);
    XCTAssertEqualObjects(empty, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#bar"]).adFragmentParameters);
    XCTAssertEqualObjects(empty, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#bar=foo=bar"]).adFragmentParameters);
    
    //At least some of the parameters are valid:
    NSDictionary* simple = @{@"foo1":@"bar1", @"foo2":@"bar2"};
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#foo1=bar1&foo2=bar2"]).adFragmentParameters);
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#foo1=bar1&foo2=bar2&foo2=bar2"]).adFragmentParameters);
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#foo1=bar1&foo2=bar2&&&"]).adFragmentParameters);
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo=bar#foo1=bar1&foo2=bar2&foo3=bar3=foo3"]).adFragmentParameters);
}

- (void)testAdQueryParameters_whenNoQPS
{
    //Negative:
    XCTAssertNil([[NSURL URLWithString:@"https://stuff.com"] adQueryParameters]);
}

- (void)testAdQueryParameters_whenSimpleQPs
{
    //Positive:
    NSDictionary *simple = @{@"foo1":@"bar1", @"foo2":@"bar2"};
    XCTAssertEqualObjects(simple, ([[NSURL URLWithString:@"https://stuff.com?foo1=bar1&foo2=bar2"] adQueryParameters]));
}

- (void)testAdQueryParameters_whenURINotURL
{
    // Valid redirect url
    NSDictionary *simple = @{@"foo1":@"bar1", @"foo2":@"bar2"};
    XCTAssertEqualObjects(simple, ([[NSURL URLWithString:@"urn:ietf:wg:oauth:2.0:oob?foo1=bar1&foo2=bar2"] adQueryParameters]));
}

- (void)testAdQueryParamters_whenMixedQueryFragment
{
    //Mixed query and fragment parameters:
    NSDictionary *simple = @{@"foo1":@"bar1", @"foo2":@"bar2"};
    XCTAssertEqualObjects(simple, ([[NSURL URLWithString:@"https://stuff.com?foo1=bar1&foo2=bar2#foo3=bar3"] adQueryParameters]));
}

- (void)testAdQueryParameters_whenContainsPercentEncoding
{
    NSDictionary *withEncoded = @{@"foo1" : @"bar1", @"foo2" : @"bar2", @"foo3=bar3" : @"foo4&bar4=bar5"};
    XCTAssertEqualObjects(withEncoded, ([[NSURL URLWithString:@"https://contoso.com?foo1=bar1&foo2=bar2&foo3%3Dbar3=foo4%26bar4%3Dbar5"] adQueryParameters]));
}

- (void)testAdHostWithPortIfNecessary_whenNoPortSpecified
{
    NSURL *url = [NSURL URLWithString:@"https://somehost.com"];
    XCTAssertEqualObjects(url.adHostWithPortIfNecessary, @"somehost.com");
}

- (void)testAdHostWithPortIfNecessary_whenStandardPortSpecified
{
    NSURL *url = [NSURL URLWithString:@"https://somehost.com:443"];
    XCTAssertEqualObjects(url.adHostWithPortIfNecessary, @"somehost.com");
}

- (void)testAdHostWithPortIfNecessary_whenNonStandardPortSpecified
{
    NSURL *url = [NSURL URLWithString:@"https://somehost.com:652"];
    XCTAssertEqualObjects(url.adHostWithPortIfNecessary, @"somehost.com:652");
}

@end
