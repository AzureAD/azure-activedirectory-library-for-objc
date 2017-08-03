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
#import "ADAuthorityValidation.h"
#import "ADAuthorityValidationRequest.h"
#import "ADDrsDiscoveryRequest.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"

#import "ADUserIdentifier.h"
#import "ADWebFingerRequest.h"
#import "XCTestCase+TestHelperMethods.h"
#import <XCTest/XCTest.h>

static NSString* const s_kTrustedAuthority = @"https://login.windows.net";

@interface ADAuthortyValidationTests : XCTestCase

@end

@implementation ADAuthortyValidationTests

- (void)setUp
{
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
    [self adTestEnd];
    [super tearDown];
}

//Does not call the server, just passes invalid authority
- (void)testValidateAuthorityError
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
    NSArray* cases = @[@"http://invalidscheme.com",
                       @"https://Invalid URL 2305 8 -0238460-820-386"];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.correlationId = [NSUUID UUID];
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    
    for (NSString* testCase in cases)
    {
        [requestParams setAuthority:testCase];
        
        XCTestExpectation* expectation = [self expectationWithDescription:@"Validate invalid authority."];
        [authorityValidation validateAuthority:requestParams
                               completionBlock:^(BOOL validated, ADAuthenticationError *error)
        {
            XCTAssertFalse(validated, @"\"%@\" should come back invalid.", testCase);
            XCTAssertNotNil(error);
            
            [expectation fulfill];
        }];
        
        [self waitForExpectationsWithTimeout:1 handler:nil];
    }
}

// Tests a normal authority
- (void)testAadNormalFlow
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
    NSString* authority = @"https://login.windows-ppe.net/common";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    [ADTestURLSession addResponse:[ADTestURLResponse responseValidAuthority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"Validate valid authority."];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError * error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation isAuthorityValidated:[NSURL URLWithString:@"https://login.windows-ppe.net"]]);
}

//Ensures that an invalid authority is not approved
- (void)testAadNonValidatedAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    [ADTestURLSession addResponse:[ADTestURLResponse responseInvalidAuthority:authority]];
    
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
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority]]);
}

- (void)testBadAadAuthorityWithValidation
{
    ADAuthenticationError* error = nil;
    
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:YES
                                                                                    error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    
    [ADTestURLSession addInvalidAuthorityResponse:authority];
    
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
}

- (void)testUnreachableAadServer
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];

    NSString* authority = @"https://login.windows.cn/MSOpenTechBV.onmicrosoft.com";

    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    
    NSURL* requestURL = [ADAuthorityValidationRequest urlForAuthorityValidation:authority trustedAuthority:s_kTrustedAuthority];
    NSString* requestURLString = [NSString stringWithFormat:@"%@&x-client-Ver=" ADAL_VERSION_STRING, requestURL.absoluteString];
    
    requestURL = [NSURL URLWithString:requestURLString];

    NSError* responseError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost userInfo:nil];

    [ADTestURLSession addResponse:[ADTestURLResponse request:requestURL
                                               respondWithError:responseError]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority when server is unreachable."];
    
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
    {
        XCTAssertFalse(validated);
        XCTAssertNotNil(error);
        
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority]]);
}

- (void)testAdfsNormalOnPrems
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
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
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseValidDrsPayload:upnSuffix
                                                                         onPrems:YES
                                                   passiveAuthenticationEndpoint:passiveEndpoint]];

    [ADTestURLSession addResponse:[ADTestURLResponse responseValidWebFinger:passiveEndpoint
                                                                     authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
    {
        XCTAssertTrue(validated);
        XCTAssertNil(error);
 
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

- (void)testAdfsNormalOnCloud
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
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
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseUnreachableDrsService:upnSuffix
                                                                               onPrems:YES]];
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseValidDrsPayload:upnSuffix
                                                                         onPrems:NO
                                                   passiveAuthenticationEndpoint:passiveEndpoint]];
    
    [ADTestURLSession addResponse:[ADTestURLResponse responseValidWebFinger:passiveEndpoint
                                                                     authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation validateAuthority:requestParams
                           completionBlock:^(BOOL validated, ADAuthenticationError *error)
    {
        XCTAssertTrue(validated);
        XCTAssertNil(error);
        
        [expectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertTrue([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

- (void)testAdfsInvalidDrs
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
    NSString* authority = @"https://login.windows.com/adfs";
    NSString* upn       = @"someuser@somehost.com";
    NSString* upnSuffix = @"somehost.com";
    
    ADAuthorityValidation* authorityValidation = [[ADAuthorityValidation alloc] init];
    ADUserIdentifier* user = [ADUserIdentifier identifierWithId:upn];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    requestParams.authority = authority;
    requestParams.correlationId = [NSUUID UUID];
    requestParams.identifier = user;
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseInvalidDrsPayload:upnSuffix onPrems:YES]];
    [ADTestURLSession addResponse: [ADTestURLResponse responseInvalidDrsPayload:upnSuffix onPrems:NO]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    
    [authorityValidation validateAuthority:requestParams
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
- (void)testAdfsInvalidWebfinger
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
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
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseValidDrsPayload:upnSuffix
                                                                         onPrems:YES
                                                   passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse: [ADTestURLResponse responseInvalidWebFinger:passiveEndpoint
                                                                        authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation validateAuthority:requestParams
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
- (void)testAdfsInvalidWebFingerNotTrusted
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
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
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseValidDrsPayload:upnSuffix
                                                                         onPrems:YES
                                                   passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse: [ADTestURLResponse responseInvalidWebFingerNotTrusted:passiveEndpoint
                                                                                  authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation validateAuthority:requestParams
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
- (void)testAdfsUnreachableWebFinger
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
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
    
    [ADTestURLSession addResponse: [ADTestURLResponse responseValidDrsPayload:upnSuffix
                                                                         onPrems:YES
                                                   passiveAuthenticationEndpoint:passiveEndpoint]];
    [ADTestURLSession addResponse: [ADTestURLResponse responseUnreachableWebFinger:passiveEndpoint authority:authority]];
    
    XCTestExpectation* expectation = [self expectationWithDescription:@"validateAuthority"];
    [authorityValidation validateAuthority:requestParams
                      completionBlock:^(BOOL validated, ADAuthenticationError *error)
    {
        XCTAssertFalse(validated);
        XCTAssertNotNil(error);
        
        [expectation fulfill];
    }];
    [self waitForExpectationsWithTimeout:1 handler:nil];
    
    XCTAssertFalse([authorityValidation isAuthorityValidated:[NSURL URLWithString:authority] domain:upnSuffix]);
}

@end
