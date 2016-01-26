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
#import "../ADALiOS/NSURL+ADExtensions.h"
#import "XCTestCase+TestHelperMethods.h"

@interface NSURLExtensionsTests : XCTestCase

@end

@implementation NSURLExtensionsTests

- (void)setUp
{
    [super setUp];
    // Put setup code here; it will be run once, before the first test case.
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [self adTestEnd];
    [super tearDown];
}

//tests the fragment extraction. Does not test any other URL logic,
//which should have been handled by the NSURL class
-(void) testFragmentParameters
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

//As both fragment and query parameters are extracted
//with the same helper method, for query parameters we have only basic tests:
-(void) testQueryParameters
{
    //Negative:
    XCTAssertNil(((NSURL*)[NSURL URLWithString:@"https://stuff.com"]).adQueryParameters);
    
    //Positive:
    NSDictionary* simple = @{@"foo1":@"bar1", @"foo2":@"bar2"};
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo1=bar1&foo2=bar2"]).adQueryParameters);
    
    //Mixed query and fragment parameters:
    XCTAssertEqualObjects(simple, ((NSURL*)[NSURL URLWithString:@"https://stuff.com?foo1=bar1&foo2=bar2#foo3=bar3"]).adQueryParameters);
}

@end
