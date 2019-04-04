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
#import "NSDictionary+ADExtensions.h"

@interface NSDictionaryExtensionTests : XCTestCase

@end

@implementation NSDictionaryExtensionTests

- (void)testAdStringForKey_whenNilKey_shouldReturnNil
{
    NSDictionary *dictionary = [NSDictionary new];
    NSString *result = [dictionary adStringForKey:nil];
    XCTAssertNil(result);
}

- (void)testAdStringForKey_whenValueMissing_shouldReturnNil
{
    NSDictionary *dictionary = @{@"key1": @"value2"};
    NSString *result = [dictionary adStringForKey:@"missing"];
    XCTAssertNil(result);
}

- (void)testAdStringForKey_whenValuePresent_andIsBlank_shouldReturnNil
{
    NSDictionary *dictionary = @{@"key1": @""};
    NSString *result = [dictionary adStringForKey:@"key1"];
    XCTAssertNil(result);
}

- (void)testAdStringForKey_whenValuePresent_andIsString_shouldReturnValue
{
    NSDictionary *dictionary = @{@"key1": @"value1"};
    NSString *result = [dictionary adStringForKey:@"key1"];
    XCTAssertEqualObjects(result, @"value1");
}

- (void)testAdStringForKey_whenValuePresent_andNotString_shouldReturnNil
{
    NSDictionary *dictionary = @{@"key1": [NSNull null]};
    NSString *result = [dictionary adStringForKey:@"key1"];
    XCTAssertNil(result);
}

@end
