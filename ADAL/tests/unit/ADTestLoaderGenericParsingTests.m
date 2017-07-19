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

@interface ADTestLoaderGenericParsingTests : XCTestCase

@end

@implementation ADTestLoaderGenericParsingTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testParsing_whenEmptyString
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@""];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertFalse([loader parse:&error]);
    XCTAssertNotNil(error);
    
    XCTAssertNil(loader.testVariables);
}

- (void)testParsing_ignoreWhitespaceBeteweenElements
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"\n\t<TestVariables>\n    <val1>value</val1>\n     <val2>value</val2>\n </TestVariables>"];
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{@"val1" : @"value", @"val2" : @"value" }));
}

- (void)testParsing_whenFileInclude
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithFile:@"test_with_include"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{ @"val1" : @"value", @"value_from_include" : @"value" }));
}

@end
