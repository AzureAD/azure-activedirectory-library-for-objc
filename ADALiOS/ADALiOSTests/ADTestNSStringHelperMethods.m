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
#import "XCTestCase+TestHelperMethods.h"

@interface ADTestNSStringHelperMethods : XCTestCase

@end

@implementation ADTestNSStringHelperMethods

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testIsStringNilOrBlankNil
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:nil], "Should return true for nil.");
}

- (void)testIsStringNilOrBlankSpace
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@" "], "Should return true for nil.");
}

- (void)testIsStringNilOrBlankTab
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\t"], "Should return true for nil.");
}

- (void)testIsStringNilOrBlankEnter
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\r"], "Should return true for nil.");
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\n"], "Should return true for nil.");
}

- (void)testIsStringNilOrBlankMixed
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@" \r\n\t  \t\r\n"], "Should return true for nil.");
}

- (void)testIsStringNilOrBlankNonEmpty
{
    //Prefix by white space:
    NSString* str = @"  text";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);
    str = @" \r\n\t  \t\r\n text";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);

    //Suffix with white space:
    str = @"text  ";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);
    str = @"text \r\n\t  \t\r\n";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);
    
    //Surrounded by white space:
    str = @"text  ";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);
    str = @" \r\n\t text  \t\r\n";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);

    //No white space:
    str = @"t";
    XCTAssertFalse([NSString adIsStringNilOrBlank:str], "Not an empty string %@", str);
}

- (void)testTrimmedString
{
    XCTAssertEqualObjects([@" \t\r\n  test" adTrimmedString], @"test");
    XCTAssertEqualObjects([@"test  \t\r\n  " adTrimmedString], @"test");
    XCTAssertEqualObjects([@"test  \t\r\n  test" adTrimmedString], @"test  \t\r\n  test");
    XCTAssertEqualObjects([@"  \t\r\n  test  \t\r\n  test  \t\r\n  " adTrimmedString], @"test  \t\r\n  test");
}


- (void)testContainsStringNil
{
    NSString* someString = @"someString";
    someString = nil;
    XCTAssertFalse([someString adContainsString:@"test"], "Should work on nil self.");
}

- (void)testContainsStringEmpty
{
    NSString* someString = @"someString";
    XCTAssertTrue([someString adContainsString:@""], "Empty string is always contained.");
    someString = @"";
    XCTAssertTrue([someString adContainsString:@""], "Empty string is always contained.");
    XCTAssertFalse([someString adContainsString:@"text"], "Empty string does not contain a real string.");
}

- (void)testContainsStringNormal
{
    NSString* someString = @"text1 text2 text3";
    XCTAssertTrue([someString adContainsString:@"text1"]);
    XCTAssertTrue([someString adContainsString:@"text2"]);
    XCTAssertTrue([someString adContainsString:@"text3"]);
    XCTAssertTrue([someString adContainsString:@"text1 text2"]);
    XCTAssertTrue([someString adContainsString:@"text2 text3"]);
    XCTAssertTrue([someString adContainsString:someString]);
 
    XCTAssertFalse([someString adContainsString:@"text4"]);
    XCTAssertFalse([someString adContainsString:@"text1 text3"]);
}

- (void)testAdUrlFormDecode
{
    NSString* testString = @"Some interesting test/+-)(*&^%$#@!~|";
    NSString* encoded = [testString adUrlFormEncode];

    XCTAssertEqualObjects(encoded, @"Some+interesting+test%2F%2B-%29%28%2A%26%5E%25%24%23%40%21~%7C");
    XCTAssertEqualObjects([encoded adUrlFormDecode], testString);
}

- (void)testAdSame
{
    NSString* text = @"a b";
    NSString* same = [NSString stringWithFormat:@"a %@", @"b"];//Generate it, just in case
    NSString* different = @"A B";
    
    XCTAssertTrue([NSString adSame:text toString:text]);
    XCTAssertTrue([NSString adSame:nil toString:nil]);
    XCTAssertTrue([NSString adSame:text toString:same]);
    XCTAssertFalse([NSString adSame:text toString:different]);
    XCTAssertFalse([NSString adSame:text toString:nil]);
    XCTAssertFalse([NSString adSame:nil toString:text]);
}

@end
