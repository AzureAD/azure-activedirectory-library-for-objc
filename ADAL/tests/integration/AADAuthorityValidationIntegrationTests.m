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


#import "ADAuthenticationContext.h"
#import "ADAuthenticationResult.h"
#import "ADAadAuthorityCache.h"
#import "ADAuthorityValidation.h"
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"

#import "NSURL+ADExtensions.h"

#import "XCTestCase+TestHelperMethods.h"
#import <XCTest/XCTest.h>

static NSString* const s_kTrustedAuthority = @"login.microsoftonline.com";

@interface AADAuthorityValidationTests : ADTestCase

@end

@implementation AADAuthorityValidationTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//Does not call the server, just passes invalid authority



- (void)testValidateAuthority_whenSchemeIsHttp_shouldFailWithError
{
    NSString *authority = @"http://invalidscheme.com";
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.correlationId = [NSUUID UUID];
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    [requestParams setAuthority:authority];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated, @"\"%@\" should come back invalid.", authority);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)testValidateAuthority_whenAuthorityUrlIsInvalid_shouldFailWithError
{
    NSString *authority = @"https://Invalid URL 2305 8 -0238460-820-386";
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.correlationId = [NSUUID UUID];
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    [requestParams setAuthority:authority];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated, @"\"%@\" should come back invalid.", authority);
         XCTAssertNotNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

// Tests a normal authority
- (void)testValidateAuthority_whenAuthorityValid_shouldPass
{
    NSString* authority = @"https://login.windows-ppe.net/common";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse validAuthority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate valid authority."];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError * error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation.aadCache tryCheckCache:[NSURL URLWithString:authority]].validated);
}

//Ensures that an invalid authority is not approved
- (void)testValidateAuthority_whenAuthorityInvalid_shouldReturnError
{
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidAuthority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError * error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    __auto_type record = [authorityValidation.aadCache tryCheckCache:[NSURL URLWithString:authority]];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
    XCTAssertNotNil(record.error);
}

- (void)testAcquireToken_whenAuthorityInvalid_shouldReturnError
{
    ADAuthenticationError* error = nil;
    
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:YES
                                                                                    error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    
    [ADTestURLSession addResponse:[ADTestAuthorityValidationResponse invalidAuthority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"acquireTokenWithResource: with invalid authority."];
    [context acquireTokenWithResource:TEST_RESOURCE
                             clientId:TEST_CLIENT_ID
                          redirectUri:TEST_REDIRECT_URL
                               userId:TEST_USER_ID
                      completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    __auto_type record = [[ADAuthorityValidation sharedInstance].aadCache tryCheckCache:[NSURL URLWithString:authority]];
    XCTAssertNotNil(record);
    XCTAssertFalse(record.validated);
}

- (void)testValidateAuthority_whenHostUnreachable_shouldFail
{
    NSString* authority = @"https://login.windows.cn/MSOpenTechBV.onmicrosoft.com";

    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    NSURL* requestURL = [ADAuthorityValidationRequest urlForAuthorityValidation:authority trustedHost:s_kTrustedAuthority];
    NSString* requestURLString = [NSString stringWithFormat:@"%@&x-client-Ver=" ADAL_VERSION_STRING, requestURL.absoluteString];
    
    requestURL = [NSURL URLWithString:requestURLString];
    
    NSError* responseError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost userInfo:nil];
    
    ADTestURLResponse *response = [ADTestURLResponse request:requestURL
                                            respondWithError:responseError];
    [response setRequestHeaders:[ADTestURLResponse defaultHeaders]];
    
    [ADTestURLSession addResponse:response];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority when server is unreachable."];
    
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
    {
        XCTAssertFalse(validated);
        XCTAssertNotNil(error);
        
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    // Failing to connect should not create a validation record
    __auto_type record = [[ADAuthorityValidation sharedInstance].aadCache tryCheckCache:[NSURL URLWithString:authority]];
    XCTAssertNil(record);
}

@end
