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
#import "NSString+ADHelperMethods.h"

@interface NSStringHelperMethodsTests : XCTestCase

@end

@implementation NSStringHelperMethodsTests

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

- (void)testFindCharacter
{
    NSString *testString = @"urn:ietf:wg:oauth:2.0:oob?code=eiofjsfjsofeoi";
    
    XCTAssertEqual(3, [testString adFindCharacter:':' start:0]);
    XCTAssertEqual(25, [testString adFindCharacter:'?' start:0]);
    
    XCTAssertEqual([testString length], [testString adFindCharacter:':' start:100]);
    XCTAssertEqual([testString length], [testString adFindCharacter:'?' start:100]);
    
    XCTAssertEqual([testString length], [testString adFindCharacter:'#' start:0]);
    
    testString = nil;
    
    XCTAssertEqual(0, [testString adFindCharacter:'@' start:10]);
}

@end
