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
#import "XCTestCase+TestHelperMethods.h"
#import "ADAuthenticationContext.h"
#import "ADTestURLConnection.h"
#import "ADAuthenticationResult.h"
#import "ADAuthorityValidation.h"

@interface ADAuthortyValidationTests : XCTestCase
{
    dispatch_semaphore_t _dsem;
}
@end

@implementation ADAuthortyValidationTests

- (void)setUp {
    _dsem = dispatch_semaphore_create(0);
    [super setUp];
    [self adTestBegin:ADAL_LOG_LEVEL_INFO];
}

- (void)tearDown
{
#if !__has_feature(objc_arc)
    dispatch_release(_dsem);
#endif
    _dsem = nil;
    
    [self adTestEnd];
    [super tearDown];
}

- (void)testIsAuthorityValidated
{
    ADAuthorityValidation* authValidation = [[ADAuthorityValidation alloc] init];
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    XCTAssertFalse([authValidation isAuthorityValidated:nil]);
    XCTAssertFalse([authValidation isAuthorityValidated:@"  "]);
    NSString* anotherHost = @"https://somedomain.com";
    XCTAssertFalse([discovery isAuthorityValidated:anotherHost]);
    XCTAssertTrue([discovery isAuthorityValidated:sAlwaysTrusted]);
    
    SAFE_ARC_RELEASE(discovery);
}


- (void)testAddValidAuthority
{
    ADInstanceDiscovery* discovery = [[ADInstanceDiscovery alloc] init];
    
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    XCTAssertFalse([discovery addValidAuthority:nil]);
    XCTAssertFalse([discovery addValidAuthority:@"  "]);
    //Test that re-adding is ok. This can happen in multi-threaded scenarios:
    XCTAssertTrue([discovery addValidAuthority:sAlwaysTrusted]);
    
    NSString* anotherHost = @"https://another.host.com";
    [discovery addValidAuthority:anotherHost];
    XCTAssertTrue([discovery isAuthorityValidated:anotherHost]);
    
    SAFE_ARC_RELEASE(discovery);
}


//Does not call the server, just passes invalid authority
-(void) testValidateAuthorityError
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    
    NSArray* cases = @[@"http://invalidscheme.com",
                       @"https://Invalid URL 2305 8 -0238460-820-386"];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID UUID]];
    
    for (NSString* testCase in cases)
    {
        ADInstanceDiscovery* discovery = [[ADInstanceDiscovery alloc] init];
        [discovery validateAuthority:testCase
                       requestParams:requestParams
                     completionBlock:^(BOOL validated, ADAuthenticationError *error)
         {
             XCTAssertFalse(validated, @"\"%@\" should come back invalid.", testCase);
             XCTAssertNotNil(error);
             
             TEST_SIGNAL;
         }];
        
        TEST_WAIT;
    }
}


// Tests a real authority
- (void)testNormalFlow
{
    ADInstanceDiscovery* discovery = [[ADInstanceDiscovery alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID UUID]];
    
    [ADTestURLConnection addResponse:[ADTestURLResponse responseValidAuthority:@"https://login.windows-ppe.net/common"]];
    
    [discovery validateAuthority:@"https://login.windows-ppe.net/common"
                   requestParams:requestParams
                 completionBlock:^(BOOL validated, ADAuthenticationError * error)
     {
         XCTAssertTrue(validated);
         XCTAssertNil(error);
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
    XCTAssertTrue([[ADAuthorityValidation sharedInstance] isAuthorityValidated:@"https://login.windows-ppe.net"]);
    SAFE_ARC_RELEASE(discovery);
    SAFE_ARC_RELEASE(requestParams);
}



//Ensures that an invalid authority is not approved
- (void)testNonValidatedAuthority
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADInstanceDiscovery* discovery = [[ADInstanceDiscovery alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID UUID]];
    
    [ADTestURLConnection addResponse:[ADTestURLResponse responseInvalidAuthority:@"https://myfakeauthority.microsoft.com/contoso.com"]];
    
    [discovery validateAuthority:@"https://MyFakeAuthority.microsoft.com/contoso.com"
                   requestParams:requestParams
                 completionBlock:^(BOOL validated, ADAuthenticationError * error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_AUTHORITY_VALIDATION);
         
         TEST_SIGNAL;
     }];
    
    TEST_WAIT;
}


- (void)testUnreachableServer
{
    [self adSetLogTolerance:ADAL_LOG_LEVEL_ERROR];
    ADInstanceDiscovery* discovery = [[ADInstanceDiscovery alloc] init];
    ADRequestParameters* requestParams = [ADRequestParameters new];
    [requestParams setCorrelationId:[NSUUID UUID]];
    
    NSURL* requestURL = [NSURL URLWithString:@"https://SomeValidURLButNotExistentInTheNet.com/common/discovery/instance?api-version=1.0&authorization_endpoint=https://login.windows.cn/MSOpenTechBV.onmicrosoft.com/oauth2/authorize&x-client-Ver=" ADAL_VERSION_STRING];
    NSError* responseError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotFindHost userInfo:nil];
    
    [ADTestURLConnection addResponse:[ADTestURLResponse request:requestURL
                                               respondWithError:responseError]];
    
    [discovery requestValidationOfAuthority:@"https://login.windows.cn/MSOpenTechBV.onmicrosoft.com"
                                       host:@"https://login.windows.cn"
                           trustedAuthority:@"https://SomeValidURLButNotExistentInTheNet.com"
                              requestParams:requestParams
                            completionBlock:^(BOOL validated, ADAuthenticationError *error)
     {
         XCTAssertFalse(validated);
         XCTAssertNotNil(error);
         
         TEST_SIGNAL;
         
     }];
    
    TEST_WAIT;
    
    SAFE_ARC_RELEASE(discovery);
    SAFE_ARC_RELEASE(requestParams);
}



- (void)testBadAuthorityWithValidation
{
    ADAuthenticationError* error = nil;
    NSString* authority = @"https://myfakeauthority.microsoft.com/contoso.com";
    ADAuthenticationContext* context = [[ADAuthenticationContext alloc] initWithAuthority:authority
                                                                        validateAuthority:YES
                                                                                    error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertNil(error);
    
    [ADTestURLConnection addInvalidAuthorityResponse:authority];
    
    __block dispatch_semaphore_t dsem = dispatch_semaphore_create(0);
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
        
        dispatch_semaphore_signal(dsem);
    }];
    
    dispatch_semaphore_wait(dsem, DISPATCH_TIME_FOREVER);
}

@end
