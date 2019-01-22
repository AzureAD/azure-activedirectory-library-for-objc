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

#import "ADALBaseUITest.h"
#import "XCTestCase+TextFieldTap.h"
#import "MSIDAutomationSuccessResult.h"

@interface ADALOnPremLoginTests : ADALBaseUITest

@end

@implementation ADALOnPremLoginTests

- (void)testInteractiveOnPremLogin_withPromptAlways_ValidateAuthorityFalse_loginHint_ADALWebView_ADFSv3
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"always";
    adfsRequest.loginHint = self.primaryAccount.account;
    adfsRequest.validateAuthority = NO;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *adfsConfig = [self configWithTestRequest:adfsRequest];
    [self acquireToken:adfsConfig];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    // ADFSv3 is not OIDC compliant and therefore userId will be missing
    XCTAssertNil([self automationSuccessResult].userInformation.legacyAccountId);
    [self closeResultView];

    // Now do silent #296725
    NSDictionary *adfsSilentConfig = [self configWithTestRequest:adfsRequest];
    [self acquireTokenSilent:adfsSilentConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do silent with user identifier
    adfsRequest.legacyAccountIdentifier = self.primaryAccount.account;
    
    NSDictionary *adfsSilentConfigWithUserId = [self configWithTestRequest:adfsRequest];
    // Acquire token silently
    [self acquireTokenSilent:adfsSilentConfigWithUserId];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Now expire access token
    [self expireAccessToken:adfsSilentConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];
    
    // Now do access token refresh
    [self acquireTokenSilent:adfsSilentConfigWithUserId];
    [self assertAccessTokenNotNil];
    XCTAssertNil([self automationSuccessResult].userInformation.legacyAccountId);
    [self closeResultView];

    // Now expire access token again
    [self expireAccessToken:adfsSilentConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh again, verifying that refresh token wasn't deleted as a result of the first operation
    [self acquireTokenSilent:adfsSilentConfigWithUserId];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testInteractiveOnpremLogin_withPromptAuto_ValidateAuthorityFalse_loginHint_ADALInWebView_ADFSv3
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"auto";
    adfsRequest.loginHint = self.primaryAccount.account;
    adfsRequest.validateAuthority = NO;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *adfsConfig = [self configWithTestRequest:adfsRequest];

    [self acquireToken:adfsConfig];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do acquiretoken again with prompt auto and expect result to be returned immediately
    [self acquireToken:adfsConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testInteractiveOnPremLogin_withPromptAlways_ValidateAuthorityTrue_noLoginHint_ADFSv3_shouldFailWithoutUPN
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"always";
    adfsRequest.validateAuthority = YES;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    
    NSDictionary *config = [self configWithTestRequest:adfsRequest];
    [self acquireToken:config];
    [self assertErrorCode:@"AD_ERROR_DEVELOPER_INVALID_ARGUMENT"];
}

// TODO: re-enable once ADFSv3 authority validation is not broken anymore
- (void)DISABLED_testInteractiveOnPremLogin_withPromptAlways_ValidateAuthorityTrue_loginHint_ADFSv3
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"always";
    adfsRequest.validateAuthority = YES;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    adfsRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:adfsRequest];
    [self acquireToken:config];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do silent #296725
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

- (void)testInteractiveOnPremLogin_withPromptAlways_ValidateAuthorityTrue_loginHint_ADALWebView_ADFSv4
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv4;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"always";
    adfsRequest.validateAuthority = YES;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    adfsRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *adfsConfig = [self configWithTestRequest:adfsRequest];
    [self acquireToken:adfsConfig];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now do silent #296725
    adfsRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentADFSConfig = [self configWithTestRequest:adfsRequest];
    [self acquireTokenSilent:silentADFSConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self automationSuccessResult].userInformation.legacyAccountId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
}

- (void)testInteractiveOnPremLogin_withPromptAlways_ValidateAuthorityFalse_loginHint_ADALWebView_ADFSv4
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionOnPrem;
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv4;
    configurationRequest.accountFeatures = @[];
    [self loadTestConfiguration:configurationRequest];
    
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.promptBehavior = @"always";
    adfsRequest.validateAuthority = NO;
    adfsRequest.configurationAuthority = self.testConfiguration.authority;
    adfsRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *adfsConfig = [self configWithTestRequest:adfsRequest];
    [self acquireToken:adfsConfig];
    [self enterADFSPassword];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self automationSuccessResult].userInformation.legacyAccountId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];

    // Now do silent #296725
    adfsRequest.legacyAccountIdentifier = self.primaryAccount.account;
    NSDictionary *silentADFSConfig = [self configWithTestRequest:adfsRequest];
    [self acquireTokenSilent:silentADFSConfig];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Now expire access token
    [self expireAccessToken:silentADFSConfig];
    [self assertAccessTokenExpired];
    [self closeResultView];

    // Now do access token refresh
    [self acquireTokenSilent:silentADFSConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self automationSuccessResult].userInformation.legacyAccountId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];

    // Now do silent #296725 without providing user ID
    adfsRequest.legacyAccountIdentifier = nil;
    silentADFSConfig = [self configWithTestRequest:adfsRequest];

    [self acquireTokenSilent:silentADFSConfig];
    [self assertAccessTokenNotNil];
    XCTAssertEqualObjects([self automationSuccessResult].userInformation.legacyAccountId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
}

#pragma mark - Private

- (void)enterADFSPassword
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
