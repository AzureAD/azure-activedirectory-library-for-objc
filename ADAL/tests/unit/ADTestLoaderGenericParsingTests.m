//
//  ADTestLoaderGenericParsingTests.m
//  ADAL
//
//  Created by Ryan Pangrle on 7/19/17.
//  Copyright © 2017 MS Open Tech. All rights reserved.
//

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
