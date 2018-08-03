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
#import "MSIDError.h"
#import "ADAuthenticationErrorConverter.h"

@interface ADAuthenticationErrorConverterIntegrationTests : XCTestCase

@end

@implementation ADAuthenticationErrorConverterIntegrationTests

/*!
 It's very easy to add an additional error in MSID space, but forget to map it to appropriate AD error.
 This test is just making sure that each error under MSIDErrorDomain is mapped to a different AD error
 and will fail if new error is added and left unmapped.
 
 This test doesn't test that the error has been mapped correctly.
 */
- (void)testErrorConversion_whenErrorConverterInitialized_shouldMapAllMSIDErrors
{
    NSDictionary *domainsAndCodes = MSIDErrorDomainsAndCodes();
    
    for (NSString *domain in domainsAndCodes)
    {
        NSArray *codes = domainsAndCodes[domain];
        for (NSNumber *code in codes)
        {
            MSIDErrorCode errorCode = [code integerValue];
            NSError *msidError = MSIDCreateError(domain, errorCode, @"test", nil, nil, nil, nil, nil);
            ADAuthenticationError *error = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError];
            
            XCTAssertNotEqual(error.code, errorCode);
            
        }
    }
}



@end
