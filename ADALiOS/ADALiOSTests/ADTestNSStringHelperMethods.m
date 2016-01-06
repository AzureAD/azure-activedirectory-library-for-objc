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

#define VERIFY_EMPTY_STRING(_str) XCTAssertTrue([NSString adIsStringNilOrBlank:_str], "+adIsStringNilOrBlank: should return true for \"%@\"", _str)
#define VERIFY_NOT_EMPTY_STRING(_str) XCTAssertFalse([NSString adIsStringNilOrBlank:_str], "+adIsStringNilOrBlank: should return false for \"%@\"", _str)

- (void)testIsStringNilOrBlankNil
{
    VERIFY_EMPTY_STRING(nil);
}

- (void) testIsStringNilOrBlankSpace
{
    VERIFY_EMPTY_STRING(@" ");
}

- (void) testIsStringNilOrBlankTab
{
    VERIFY_EMPTY_STRING(@"\t");
}

- (void) testIsStringNilOrBlankEnter
{
    VERIFY_EMPTY_STRING(@"\r");
    VERIFY_EMPTY_STRING(@"\n");
    VERIFY_EMPTY_STRING(@"\r\n");
}

- (void) testIsStringNilOrBlankMixed
{
    VERIFY_EMPTY_STRING(@" \r\n\t  \t\r\n");
}

- (void) testIsStringNilOrBlankNonEmpty
{
    VERIFY_NOT_EMPTY_STRING(@"  text");
    VERIFY_NOT_EMPTY_STRING(@" \r\n\t  \t\r\n text");

    VERIFY_NOT_EMPTY_STRING(@"text  ");
    VERIFY_NOT_EMPTY_STRING(@"text \r\n\t  \t\r\n");
    
    //Surrounded by white space:
    VERIFY_NOT_EMPTY_STRING(@"  text  ");
    VERIFY_NOT_EMPTY_STRING(@" \r\n\t text  \t\r\n");

    //No white space:
    VERIFY_NOT_EMPTY_STRING(@"t");
    VERIFY_NOT_EMPTY_STRING(@"0");
}

-(void) testTrimmedString
{
    XCTAssertEqualObjects([@" \t\r\n  test" adTrimmedString], @"test");
    XCTAssertEqualObjects([@"test  \t\r\n  " adTrimmedString], @"test");
    XCTAssertEqualObjects([@"test  \t\r\n  test" adTrimmedString], @"test  \t\r\n  test");
    XCTAssertEqualObjects([@"  \t\r\n  test  \t\r\n  test  \t\r\n  " adTrimmedString], @"test  \t\r\n  test");
}


-(void) testContainsStringNil
{
    NSString* someString = @"someString";
    someString = nil;
    XCTAssertFalse([someString adContainsString:@"test"], "Should work on nil self.");
}

-(void) testContainsStringEmpty
{
    NSString* someString = @"someString";
    XCTAssertTrue([someString adContainsString:@""], "Empty string is always contained.");
    someString = @"";
    XCTAssertTrue([someString adContainsString:@""], "Empty string is always contained.");
    XCTAssertFalse([someString adContainsString:@"text"], "Empty string does not contain a real string.");
}

-(void) testContainsStringNormal
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

//Checks base64 URL encoding and decoding:
-(void) verifyBase64:(NSString*) original
            expected:(NSString*) expected
{
    NSString* encoded = [original adBase64UrlEncode];
    NSString* decoded = [encoded adBase64UrlDecode];
    XCTAssertEqualObjects(encoded, expected);
    XCTAssertEqualObjects(decoded, original);
}

-(void) testBase64
{
    NSString* encodeEmpty = [@"" adBase64UrlEncode];
    XCTAssertEqualObjects(encodeEmpty, @"");
    
    NSString* decodeEmpty = [@"" adBase64UrlDecode];
    XCTAssertEqualObjects(decodeEmpty, @"");
    
    //15 characters, aka 3k:
    NSString* test1 = @"1$)=- \t\r\nfoo%^!";
    [self verifyBase64:test1 expected:@"MSQpPS0gCQ0KZm9vJV4h"];
    
    //16 characters, aka 3k + 1:
    NSString* test2 = [test1 stringByAppendingString:@"@"];
    [self verifyBase64:test2 expected:@"MSQpPS0gCQ0KZm9vJV4hQA"];
    
    //17 characters, aka 3k + 2:
    NSString* test3 = [test2 stringByAppendingString:@"<"];
    [self verifyBase64:test3 expected:@"MSQpPS0gCQ0KZm9vJV4hQDw"];
    
    //Ensure that URL encoded is in place through encoding correctly the '+' and '/' signs (just in case)
    [self verifyBase64:@"++++/////" expected:@"KysrKy8vLy8v"];
    
    //Decode invalid:
    XCTAssertFalse([@" " adBase64UrlDecode].length, "Contains non-suppurted character < 128");
    XCTAssertFalse([@"™" adBase64UrlDecode].length, "Contains characters beyond 128");
    XCTAssertFalse([@"денят" adBase64UrlDecode].length, "Contains unicode characters.");
    
}

-(void) testAdUrlFormDecode
{
    NSString* testString = @"Some interesting test/+-)(*&^%$#@!~|";
    NSString* encoded = [testString adUrlFormEncode];

    XCTAssertEqualObjects(encoded, @"Some+interesting+test%2F%2B-%29%28%2A%26%5E%25%24%23%40%21~%7C");
    XCTAssertEqualObjects([encoded adUrlFormDecode], testString);
}

-(void) testAdSame
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
