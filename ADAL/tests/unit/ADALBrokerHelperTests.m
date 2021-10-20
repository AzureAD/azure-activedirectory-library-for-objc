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
#import "ADALBrokerHelper.h"
#import "ADALAppExtensionUtil.h"
#import "ADApplicationTestUtil.h"

@interface ADALBrokerHelperTests : XCTestCase

@end

@implementation ADALBrokerHelperTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    ADApplicationTestUtil.allowedSchemes = nil;
    [super tearDown];
}

- (void)testCanUseBroker_whenInvokeOnMainThread_ShouldReturnTrue
{
    BOOL result = [ADALBrokerHelper canUseBroker];
    
    XCTAssertTrue(result);
}

- (void)testCanUseBroker_whenInvokeOnBgThread_ShouldReturnTrue
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get result from +canUseBroker on bg thread."];
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
        BOOL result = [ADALBrokerHelper canUseBroker];
        XCTAssertTrue(result);
        
        [expectation fulfill];
    });
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testCanUseBroker_wheniOS13AndOldBrokerInstalled_shouldReturnFalse
{
    if (@available(iOS 13.0, *))
    {
        ADApplicationTestUtil.allowedSchemes = @[@"msauth"];
        
        BOOL result = [ADALBrokerHelper canUseBroker];
        XCTAssertFalse(result);
    }
}

- (void)testCanUseBroker_wheniOS13AndNewBrokerInstalled_shouldReturnTrue
{
    if (@available(iOS 13.0, *))
    {
        ADApplicationTestUtil.allowedSchemes = @[@"msauth", @"msauthv3"];
        
        BOOL result = [ADALBrokerHelper canUseBroker];
        XCTAssertTrue(result);
    }
}

@end
