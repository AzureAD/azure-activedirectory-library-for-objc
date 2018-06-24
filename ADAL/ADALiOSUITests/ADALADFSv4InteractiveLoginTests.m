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

@interface ADALADFSv4InteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALADFSv4InteractiveLoginTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv4;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 11
- (void)testInteractiveADFSv4Login_withPromptAlways_noLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES
                             };
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    [self aadEnterEmail];
    [self enterADFSv4Password];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
    [self closeAuthUI];
    [self closeResultView];

    // Now do silent #296725
    NSDictionary *silentParams = @{
                                   @"user_identifier" : self.primaryAccount.account,
                                   @"client_id" : self.testConfiguration.clientId,
                                   @"authority" : self.testConfiguration.authority,
                                   @"resource" : self.testConfiguration.resource
                                   };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
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
    [self closeResultView];

    // Now do silent #296725 without providing user ID
    silentParams = @{
                     @"client_id" : self.testConfiguration.clientId,
                     @"authority" : self.testConfiguration.authority,
                     @"resource" : self.testConfiguration.resource
                     };

    config = [self.testConfiguration configWithAdditionalConfiguration:silentParams];
    [self acquireTokenSilent:config];
    [self assertAccessTokenNotNil];
    [self closeResultView];
}

// #290995 iteration 12
- (void)testInteractiveADFSv4Login_withPromptAlways_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable"
                             };
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];

    [self acquireToken:config];

    [self enterADFSv4Password];

    [self assertAccessTokenNotNil];
    [self closeResultView];

    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)enterADFSv4Password
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
