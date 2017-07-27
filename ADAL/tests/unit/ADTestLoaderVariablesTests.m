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

@interface ADTestLoaderVariablesTests : XCTestCase

@end

@implementation ADTestLoaderVariablesTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testVariables_whenEmpty
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<TestVariables></TestVariables>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqual(testVariables.count, 0);
}

- (void)testVariables_whenSingleLevel
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<TestVariables><val1>value 1</val1><val2>value 2</val2></TestVariables>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{ @"val1" : @"value 1", @"val2" : @"value 2" }));
}

- (void)testVariables_whenMultipleLevels
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<TestVariables><val1>value 1</val1><val2>value 2</val2><val3><val4>value 4</val4></val3></TestVariables>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{ @"val1" : @"value 1", @"val2" : @"value 2", @"val3" : @{ @"val4" : @"value 4" } }));
}

- (void)testVariables_typeJwt
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<TestVariables><val type=\"jwt\"><part>{\"jsonkey\":\"jsonval\"}</part><part>{ \"morejson\" : 2500 }</part></val></TestVariables>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{ @"val" : @"eyJqc29ua2V5IjoianNvbnZhbCJ9.eyJtb3JlanNvbiI6MjUwMH0" }));
}

- (void)testVariables_typeJwtIdToken
{
    ADTestLoader *loader = [[ADTestLoader alloc] initWithString:@"<TestVariables><val type=\"jwt\"><part>{\"typ\":\"JWT\", \"alg\":\"none\"}</part><part>{ \"upn\" : \"user@contoso.com\" }</part></val></TestVariables>"];
    XCTAssertNotNil(loader);
    
    NSError *error = nil;
    XCTAssertTrue([loader parse:&error]);
    XCTAssertNil(error);
    
    NSDictionary *testVariables = loader.testVariables;
    XCTAssertNotNil(testVariables);
    XCTAssertEqualObjects(testVariables, (@{ @"val" : @"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1cG4iOiJ1c2VyQGNvbnRvc28uY29tIn0" }));
}

@end
