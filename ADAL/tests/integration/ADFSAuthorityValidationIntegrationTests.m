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

#import "ADAuthorityValidation.h"
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"

@interface ADFSAuthorityValidationTests : ADTestCase

@end

@implementation ADFSAuthorityValidationTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testCheckAuthority_whenAuthorityOnPremsValid_shouldPass
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    NSString* passiveEndpoint = @"https://somepassiveauth.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse: [ADTestAuthorityValidationResponse validDrsPayload:upnSuffix
                                                                              onPrems:YES
                                                        passiveAuthenticationEndpoint:passiveEndpoint]];
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validWebFinger:passiveEndpoint
                                                                          authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

- (void)testCheckAuthority_whenAuthorityOnCloudValid_shouldPass
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    NSString* passiveEndpoint = @"https://somepassiveauth.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse unreachableDrsService:upnSuffix
                                                                                   onPrems:YES]];
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validDrsPayload:upnSuffix
                                                                             onPrems:NO
                                                       passiveAuthenticationEndpoint:passiveEndpoint]];
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validWebFinger:passiveEndpoint
                                                                          authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

- (void)testCheckAuthority_whenInvalidDrs_shuoldFail
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidDrsPayload:upnSuffix
                                                                               onPrems:YES]];
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidDrsPayload:upnSuffix
                                                                               onPrems:NO]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

// test invalid webfinger - 400
- (void)testCheckAuthority_whenInvalidWebFinger_shouldFail
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    NSString* passiveEndpoint = @"https://somepassiveauth.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validDrsPayload:upnSuffix
                                                                             onPrems:YES
                                                       passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidWebFinger:passiveEndpoint
                                                                            authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

// test invalid webfinger - 200 but not match
- (void)testCheckAuthority_whenWebFingerNotTrusted_shouldFail
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    NSString* passiveEndpoint = @"https://somepassiveauth.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validDrsPayload:upnSuffix
                                                                             onPrems:YES
                                                       passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidWebFingerNotTrusted:passiveEndpoint
                                                                                      authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

// test invalid webfinger - not reachable
- (void)testCheckAuthority_whenWebFingerNotReachable_shouldFail
{
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    NSString* passiveEndpoint = @"https://somepassiveauth.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validDrsPayload:upnSuffix
                                                                             onPrems:YES
                                                       passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse unreachableWebFinger:passiveEndpoint
                                                                                authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation checkAuthority:requestParams
                      validateAuthority:YES
                        completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

// test
- (void)testCheckAuthority_whenValidationTurnedOffAndAdfsAuthority_shouldPass
{
    {
        NSString* authority = @"https://login.windows.com/adfs";
        
        ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
        
        ADRequestParameters* requestParams = [ADRequestParameters new];
        requestParams.authority = authority;
        requestParams.correlationId = [NSUUID UUID];
        
        XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
        [authorityValidation checkAuthority:requestParams
                          validateAuthority:NO
                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             XCTAssertFalse(validated);
             XCTAssertNil(error);
             
             [expectation fulfill];
         }];
        [self waitForExpectationsWithTimeout:1 handler:nil];
}


}
@end
