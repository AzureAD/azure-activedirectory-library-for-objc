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

#import "ADALBaseAADUITest.h"
#import "MSIDAutomationSuccessResult.h"
#import "MSIDAADIdTokenClaimsFactory.h"

@implementation ADALBaseAADUITest

- (NSString *)runSharedAADLoginWithTestRequest:(MSIDAutomationTestRequest *)request
{
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    [self assertAuthUIAppear];
    
    if (request.usePassedWebView)
    {
        XCTAssertTrue(self.testApp.staticTexts[@"PassedIN"]);
    }
    
    if (!request.loginHint && !request.homeAccountIdentifier)
    {
        [self aadEnterEmail];
    }
    
    [self aadEnterPassword];
    NSString *userId = [self runSharedResultAssertionWithTestRequest:request];
    [self closeResultView];
    return userId;
}

- (void)runSharedSilentAADLoginWithTestRequest:(MSIDAutomationTestRequest *)request
{
    NSDictionary *config = [self configWithTestRequest:request];
    // Acquire token silently
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Now expire access token
    [self expireAccessToken:config];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    // Now do access token refresh
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self runSharedResultAssertionWithTestRequest:request];
    [self closeResultView];
}

- (void)runSharedAuthUIAppearsStepWithTestRequest:(MSIDAutomationTestRequest *)request
{
    NSDictionary *config = [self configWithTestRequest:request];
    [self acquireToken:config];
    
    [self assertAuthUIAppear];
    [self closeAuthUI];
    
    [self assertErrorCode:@"AD_ERROR_UI_USER_CANCEL"];
    [self closeResultView];
}

- (NSString *)runSharedResultAssertionWithTestRequest:(MSIDAutomationTestRequest *)request
{
    [self assertAccessTokenNotNil];
    
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    XCTAssertNotNil(result.userInformation.legacyAccountId);
    
    if (request.testAccount)
    {
        NSString *resultTenantId = result.userInformation.tenantId;
        
        NSString *idToken = result.idToken;
        XCTAssertNotNil(idToken);
        
        MSIDIdTokenClaims *claims = [MSIDAADIdTokenClaimsFactory claimsFromRawIdToken:idToken error:nil];
        XCTAssertNotNil(idToken);
        
        NSString *idTokenTenantId = claims.jsonDictionary[@"tid"];
        
        XCTAssertEqualObjects(resultTenantId, request.testAccount.targetTenantId);
        XCTAssertEqualObjects(resultTenantId, idTokenTenantId);
    }
    
    return result.userInformation.legacyAccountId;
}

@end
