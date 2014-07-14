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

- (void) testIsStringNilOrBlankSpace
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@" "], "Should return true for nil.");
}

- (void) testIsStringNilOrBlankTab
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\t"], "Should return true for nil.");
}

- (void) testIsStringNilOrBlankEnter
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\r"], "Should return true for nil.");
    XCTAssertTrue([NSString adIsStringNilOrBlank:@"\n"], "Should return true for nil.");
}

- (void) testIsStringNilOrBlankMixed
{
    XCTAssertTrue([NSString adIsStringNilOrBlank:@" \r\n\t  \t\r\n"], "Should return true for nil.");
}

- (void) testIsStringNilOrBlankNonEmpty
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

-(void) testTrimmedString
{
    ADAssertStringEquals([@" \t\r\n  test" adTrimmedString], @"test");
    ADAssertStringEquals([@"test  \t\r\n  " adTrimmedString], @"test");
    ADAssertStringEquals([@"test  \t\r\n  test" adTrimmedString], @"test  \t\r\n  test");
    ADAssertStringEquals([@"  \t\r\n  test  \t\r\n  test  \t\r\n  " adTrimmedString], @"test  \t\r\n  test");
}


-(void) testContainsStringNil
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    NSString* someString = @"someString";
    XCTAssertThrowsSpecificNamed([someString adContainsString:nil],
                                 NSException, NSInvalidArgumentException, "Nil argument name should throw.");
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

-(void) testRangeHasPrefix
{
    NSString* prefix = @"Prefix word";
    //Negative
    NSRange range = {0, prefix.length};
    XCTAssertFalse([@" Prefix word" adRangeHasPrefixWord:prefix range:range], "Starts with another character");
    --range.length;
    range.location = 1;
    XCTAssertFalse([@" Prefix word" adRangeHasPrefixWord:prefix range:range], "Shorter range");
    range.length = prefix.length;//Restore
    range.location = 1;
    XCTAssertFalse([@" Prefix wor" adRangeHasPrefixWord:prefix range:range], "Incomplete prefix");
    range.length = 100;
    XCTAssertFalse([@" Prefix word1" adRangeHasPrefixWord:prefix range:range], "Additional characters at the end");
    range.location = 100;
    XCTAssertFalse([@" Prefix word" adRangeHasPrefixWord:prefix range:range], "Range beyond the end.");
    
    //Positive
    range.length = 100;//Big enough
    range.location = 1;
    XCTAssertTrue([@" Prefix word" adRangeHasPrefixWord:prefix range:range]);
    XCTAssertTrue([@"PPrefix word" adRangeHasPrefixWord:prefix range:range]);
    XCTAssertTrue([@"PPrefix word another thing" adRangeHasPrefixWord:prefix range:range]);
    XCTAssertTrue([@"Any string" adRangeHasPrefixWord:@"" range:range]);
}

-(void) testSubstringHasPrefixWord
{
    NSString* prefix = @"Prefix word";
    //Negative
    XCTAssertFalse([@" Prefix word" adSubstringHasPrefixWord:prefix start:0], "Starts with another character");
    XCTAssertFalse([@" Prefix wor" adSubstringHasPrefixWord:prefix start:1], "Incomplete prefix");
    XCTAssertFalse([@" Prefix word1" adSubstringHasPrefixWord:prefix start:1], "Additional characters at the end");
    XCTAssertFalse([@" Prefix word" adSubstringHasPrefixWord:prefix start:2], "Range beyond the end.");
    XCTAssertFalse([@" Prefix word" adSubstringHasPrefixWord:prefix start:100], "Range beyond the end.");
    
    //Positive
    XCTAssertTrue([@" Prefix word" adSubstringHasPrefixWord:prefix start: 1]);
    XCTAssertTrue([@"PPrefix word" adSubstringHasPrefixWord:prefix start: 1]);
    XCTAssertTrue([@"PPrefix word another thing" adSubstringHasPrefixWord:prefix start: 1]);
}

-(void) testFindNonWhiteCharacterAfter
{
    //Starting at 0:
    ADAssertLongEquals(0, [@"" adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(1, [@" " adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(1, [@"\t" adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(2, [@" \t" adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(2, [@"\t " adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(2, [@" \tasdba" adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(3, [@"\t  asdfa  \t" adFindNonWhiteCharacterAfter:0]);
    
    //Starting beyond or at the string length:
    ADAssertLongEquals(0, [@"" adFindNonWhiteCharacterAfter:0]);
    ADAssertLongEquals(1, [@" " adFindNonWhiteCharacterAfter:1]);
    ADAssertLongEquals(1, [@"\t" adFindNonWhiteCharacterAfter:3]);
    ADAssertLongEquals(2, [@" \t" adFindNonWhiteCharacterAfter:5]);
    ADAssertLongEquals(2, [@"\t " adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(7, [@" \tasdba" adFindNonWhiteCharacterAfter:12]);
    ADAssertLongEquals(11, [@"\t  asdfa  \t" adFindNonWhiteCharacterAfter:11]);
    
    //Skip some characters
    ADAssertLongEquals(2, [@"ab" adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(3, [@"12 " adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(2, [@"1\t" adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(4, [@"12 \t" adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(2, [@"123\t " adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(4, [@"12 \tasdba" adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(5, [@"12\t  asdfa  \t" adFindNonWhiteCharacterAfter:2]);
    ADAssertLongEquals(2, [@" \ta\t " adFindNonWhiteCharacterAfter:2]);
}

-(void) testFindCharacter
{
    //Starting at 0:
    ADAssertLongEquals(0, [@"" adFindCharacter:'#' start: 0]);
    ADAssertLongEquals(1, [@" " adFindCharacter:'#' start: 0]);
    ADAssertLongEquals(1, [@" ##" adFindCharacter:'#' start: 0]);
    ADAssertLongEquals(1, [@" ##  " adFindCharacter:'#' start: 0]);
    ADAssertLongEquals(0, [@"# #" adFindCharacter:'#' start: 0]);
    ADAssertLongEquals(0, [@"#" adFindCharacter:'#' start: 0]);

    //Start beyond the end
    ADAssertLongEquals(0, [@"" adFindCharacter:'#' start:0]);
    ADAssertLongEquals(0, [@"" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(1, [@"#" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(2, [@"##" adFindCharacter:'#' start:2]);
    ADAssertLongEquals(2, [@"a#" adFindCharacter:'#' start:5]);
    ADAssertLongEquals(2, [@"#a" adFindCharacter:'#' start:5]);

    //Skip leading characters:
    ADAssertLongEquals(1, [@"#" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(1, [@"#" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(1, [@"##" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(6, [@"aadfas#" adFindCharacter:'#' start:1]);
    ADAssertLongEquals(2, [@"#a#" adFindCharacter:'#' start:1]);
}

//Checks base64 URL encoding and decoding:
-(void) verifyBase64:(NSString*) original
            expected:(NSString*) expected
{
    NSString* encoded = [original adBase64UrlEncode];
    NSString* decoded = [encoded adBase64UrlDecode];
    ADAssertStringEquals(encoded, expected);
    ADAssertStringEquals(decoded, original);
}

-(void) testBase64
{
    NSString* encodeEmpty = [@"" adBase64UrlEncode];
    ADAssertStringEquals(encodeEmpty, @"");
    
    NSString* decodeEmpty = [@"" adBase64UrlDecode];
    ADAssertStringEquals(decodeEmpty, @"");
    
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

    ADAssertStringEquals(encoded, @"Some+interesting+test%2F%2B-%29%28%2A%26%5E%25%24%23%40%21~%7C");
    ADAssertStringEquals([encoded adUrlFormDecode], testString);
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
