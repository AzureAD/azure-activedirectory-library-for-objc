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
#import "XCTestCase+TestHelperMethods.h"

@interface ADTestNSStringHelperMethods : XCTestCase

@end

@implementation ADTestNSStringHelperMethods

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
    [self adTestEnd];
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

#define VERIFY_BASE64(_ORIGINAL, _EXPECTED) { \
    NSString* encoded = [_ORIGINAL adBase64UrlEncode]; \
    NSString* decoded = [_EXPECTED adBase64UrlDecode]; \
    XCTAssertEqualObjects(encoded, _EXPECTED); \
    XCTAssertEqualObjects(decoded, _ORIGINAL); \
}

- (void)testBase64
{
    NSString* encodeEmpty = [@"" adBase64UrlEncode];
    XCTAssertEqualObjects(encodeEmpty, @"");
    
    NSString* decodeEmpty = [@"" adBase64UrlDecode];
    XCTAssertEqualObjects(decodeEmpty, @"");
    
    //15 characters, aka 3k:
    NSString* test1 = @"1$)=- \t\r\nfoo%^!";
    VERIFY_BASE64(test1, @"MSQpPS0gCQ0KZm9vJV4h");
    
    //16 characters, aka 3k + 1:
    NSString* test2 = [test1 stringByAppendingString:@"@"];
    VERIFY_BASE64(test2, @"MSQpPS0gCQ0KZm9vJV4hQA");
    
    //17 characters, aka 3k + 2:
    NSString* test3 = [test2 stringByAppendingString:@"<"];
    VERIFY_BASE64(test3, @"MSQpPS0gCQ0KZm9vJV4hQDw");
    
    //Ensure that URL encoded is in place through encoding correctly the '+' and '/' signs (just in case)
    VERIFY_BASE64(@"++++/////", @"KysrKy8vLy8v");
    
    //Decode invalid:
    XCTAssertFalse([@" " adBase64UrlDecode].length, "Contains non-suppurted character < 128");
    XCTAssertFalse([@"™" adBase64UrlDecode].length, "Contains characters beyond 128");
    XCTAssertFalse([@"денят" adBase64UrlDecode].length, "Contains unicode characters.");
}

- (void)testAdUrlFormDecode
{
    NSString* testString = @"Some interesting test/+-)(*&^%$#@!~|";
    NSString* encoded = [testString adUrlFormEncode];

    XCTAssertEqualObjects(encoded, @"Some+interesting+test%2F%2B-%29%28%2A%26%5E%25%24%23%40%21~%7C");
    XCTAssertEqualObjects([encoded adUrlFormDecode], testString);
}

@end
