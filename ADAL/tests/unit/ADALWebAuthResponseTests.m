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
#import "ADALWebAuthResponse.h"
#import "ADALWebAuthRequest.h"

@interface ADALWebAuthResponseTests : ADTestCase

@end

@implementation ADALWebAuthResponseTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testAuthParams
{
    NSString* pkeyAuthString = @"nonce=\"I am a nonce!\", CertAuthorities=\"OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97,CN=MS-Organization-Access,DC=windows,DC=net\", Version=\"1.0\", Context=\"Look at me! I'm a context!\"";
    
    NSDictionary* expected = @{ @"nonce" : @"I am a nonce!",
                                @"CertAuthorities" : @"OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97,CN=MS-Organization-Access,DC=windows,DC=net",
                                @"Version" : @"1.0",
                                @"Context" : @"Look at me! I'm a context!"
                                };
    
    NSDictionary* authHeaders = [ADALWebAuthResponse parseAuthHeader:pkeyAuthString];
    
    XCTAssertEqualObjects(expected, authHeaders);
}

- (void)testAuthParamErrors
{
    NSString* unterminatedString = @"key1=\"value1\",key2=\"value2";
    XCTAssertNil([ADALWebAuthResponse parseAuthHeader:unterminatedString]);
    
    NSString* tooManyCommas = @"key1=\"value1\",,,,,,,key2=\"value2\"";
    XCTAssertNil([ADALWebAuthResponse parseAuthHeader:tooManyCommas]);
    
    NSString* nothingButCommas = @",,,,,,,,,,,,";
    XCTAssertNil([ADALWebAuthResponse parseAuthHeader:nothingButCommas]);
    
    NSString* emptyString = @"";
    // In this case we expect an empty dictionary back
    XCTAssertEqualObjects([ADALWebAuthResponse parseAuthHeader:emptyString], @{});
    
    NSString* noComma = @"key1=\"value1\"key2=\"value2\"";
    XCTAssertNil([ADALWebAuthResponse parseAuthHeader:noComma]);
}

- (void)testProcessError_whenErrorContainsFailedUrlKey_shouldRemoveParametersFromUrl
{
    __auto_type url = [[NSURL alloc] initWithString:@"https://example.com"];
    __auto_type request = [[ADALWebAuthRequest alloc] initWithURL:url context:nil];
    __auto_type failedUrl = [[NSURL alloc] initWithString:@"myapp://com.myapp/?code=some_code_value&session_state=12345678&x-client-Ver=2.6.4"];
    __auto_type userInfo = @{
                             NSLocalizedDescriptionKey: @"unsupported URL",
                             NSURLErrorFailingURLErrorKey: failedUrl,
                             NSURLErrorFailingURLStringErrorKey: failedUrl.absoluteString,
                             };
    __auto_type error = [[NSError alloc] initWithDomain:@"test.com" code:1 userInfo:userInfo];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"process error"];
    [ADALWebAuthResponse processError:error
                            request:request
                         completion:^(ADALAuthenticationError *adError, NSMutableDictionary __unused *dictionary)
     {
         __auto_type expectedUrl = [[NSURL alloc] initWithString:@"myapp://com.myapp/"];
         __auto_type expectedUserInfo = @{
                                          NSLocalizedDescriptionKey: @"unsupported URL",
                                          NSURLErrorFailingURLErrorKey: expectedUrl,
                                          NSURLErrorFailingURLStringErrorKey: expectedUrl.absoluteString,
                                          };
         
         XCTAssertEqualObjects(expectedUserInfo, adError.userInfo);
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

@end
