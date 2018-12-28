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
#import "ADAuthenticationErrorMap.h"

@interface ADAuthenticationErrorMapTests : XCTestCase

@end

@implementation ADAuthenticationErrorMapTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}


- (void)testErrorDomainFromMsidError_whenNoError_shouldReturnNil
{
    NSErrorDomain newDomain = [ADAuthenticationErrorMap adErrorDomainFromMsidError:nil];
    XCTAssertNil(newDomain);
}

- (void)testErrorDomainFromMsidError_whenMappableError_shouldReturnMappedDomain
{
    NSError *msidError = MSIDCreateError(MSIDErrorDomain, MSIDErrorInternal, nil, nil, nil, nil, nil, nil);
    NSErrorDomain newDomain = [ADAuthenticationErrorMap adErrorDomainFromMsidError:msidError];
    NSString *expectedErrorDomain = ADAuthenticationErrorDomain;
    XCTAssertEqualObjects(newDomain, expectedErrorDomain);
}

- (void)testErrorDomainFromMsidError_whenNotMappableError_shouldReturnNil
{
    NSError *msidError = MSIDCreateError(NSURLErrorDomain, NSURLErrorUnknown, nil, nil, nil, nil, nil, nil);
    XCTAssertNil(msidError);
}

- (void)testErrorCodeFromMsidError_whenMappedDomainAndMappableCode_shouldReturnMappedCode
{
    NSError *msidError = MSIDCreateError(MSIDErrorDomain, MSIDErrorInternal, nil, nil, nil, nil, nil, nil);
    NSInteger code = [ADAuthenticationErrorMap adErrorCodeFromMsidError:msidError];
    NSInteger expectedErrorCode = AD_ERROR_UNEXPECTED;
    XCTAssertEqual(code, expectedErrorCode);
}

- (void)testErrorCodeFromMsidError_whenMappedDomainAndUnmappableCode_shouldThrowAssert
{
    NSError *msidError = MSIDCreateError(MSIDErrorDomain, 99999, nil, nil, nil, nil, nil, nil);
    XCTAssertThrows([ADAuthenticationErrorMap adErrorCodeFromMsidError:msidError]);
}

- (void)testErrorCodeFromMsidError_whenUnmappedDomain_shouldReturnCodeAsIs
{
    NSError *msidError = MSIDCreateError(NSURLErrorDomain, NSURLErrorUnknown, nil, nil, nil, nil, nil, nil);
    NSInteger code = [ADAuthenticationErrorMap adErrorCodeFromMsidError:msidError];
    NSInteger expectedErrorCode = NSURLErrorUnknown;
    XCTAssertEqual(code, expectedErrorCode);
}

@end
