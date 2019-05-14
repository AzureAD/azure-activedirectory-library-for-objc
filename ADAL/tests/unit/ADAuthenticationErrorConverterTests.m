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
#import "ADAuthenticationError.h"
#import "ADAuthenticationErrorConverter.h"
#import "MSIDError.h"

@interface ADAuthenticationErrorConverterTests : XCTestCase

@end

@implementation ADAuthenticationErrorConverterTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testErrorConversion_whenPassInNil_shouldReturnNil {
    NSError *adalError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:nil];
    XCTAssertNil(adalError);
}

- (void)testErrorConversion_whenOnlyErrorDomainIsMapped_shouldKeepErrorCode {
    NSInteger errorCode = -9999;
    NSString *errorDescription = @"a fake error description.";
    NSString *oauthError = @"a fake oauth error message.";
    NSError *underlyingError = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecItemNotFound userInfo:nil];
    NSUUID *correlationId = [NSUUID UUID];
    NSDictionary *httpHeaders = @{@"fake header key" : @"fake header value"};
    
    NSError *msidError = MSIDCreateError(MSIDErrorDomain,
                                         errorCode,
                                         errorDescription,
                                         oauthError,
                                         nil,
                                         underlyingError,
                                         correlationId,
                                         @{MSIDHTTPHeadersKey : httpHeaders});
    ADAuthenticationError *adalError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError];
    
    XCTAssertNotNil(adalError);
    XCTAssertEqualObjects(adalError.domain, ADAuthenticationErrorDomain);
    XCTAssertEqual(adalError.code, errorCode);
    XCTAssertEqualObjects(adalError.errorDetails, errorDescription);
    XCTAssertEqualObjects(adalError.protocolCode, oauthError);
    XCTAssertEqualObjects(adalError.userInfo[NSUnderlyingErrorKey], underlyingError);
    XCTAssertEqualObjects(adalError.userInfo[ADHTTPHeadersKey], httpHeaders);
}

- (void)testErrorConversion_whenBothErrorDomainAndCodeAreMapped_shouldMapBoth {
    NSString *domain = MSIDErrorDomain;
    NSString *expectedDomain = ADAuthenticationErrorDomain;
    NSInteger errorCode = MSIDErrorAuthorityValidation;
    NSInteger expectedMappedErrorCode = AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION;
    
    NSString *errorDescription = @"a fake error description.";
    NSString *oauthError = @"a fake oauth error message.";
    NSError *underlyingError = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecItemNotFound userInfo:nil];
    NSUUID *correlationId = [NSUUID UUID];
    NSDictionary *httpHeaders = @{@"fake header key" : @"fake header value"};
    
    NSError *msidError = MSIDCreateError(domain,
                                         errorCode,
                                         errorDescription,
                                         oauthError,
                                         nil,
                                         underlyingError,
                                         correlationId,
                                         @{MSIDHTTPHeadersKey : httpHeaders});
    ADAuthenticationError *adalError = [ADAuthenticationErrorConverter ADAuthenticationErrorFromMSIDError:msidError];
    
    XCTAssertNotNil(adalError);
    XCTAssertEqualObjects(adalError.domain, expectedDomain);
    XCTAssertEqual(adalError.code, expectedMappedErrorCode);
    XCTAssertEqualObjects(adalError.errorDetails, errorDescription);
    XCTAssertEqualObjects(adalError.protocolCode, oauthError);
    XCTAssertEqualObjects(adalError.userInfo[NSUnderlyingErrorKey], underlyingError);
    XCTAssertEqualObjects(adalError.userInfo[ADHTTPHeadersKey], httpHeaders);
}

@end
