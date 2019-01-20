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
#import "ADALBaseUITest.h"
#import "NSDictionary+ADALiOSUITests.h"
#import "XCTestCase+TextFieldTap.h"

@interface ADALADFSv3InteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALADFSv3InteractiveLoginTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderADfsv3;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 11
- (void)testInteractiveADFSv3Login_withPromptAlways_noLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.validateAuthority = YES;
    adfsRequest.uiBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:adfsRequest];
    [self acquireToken:config];
    
    [self aadEnterEmail];
    [self enterADFSv3Password];
    
    [self assertAccessTokenNotNil];
    NSString *userId = [self runSharedResultAssertionWithTestRequest:adfsRequest];
    // ADFSv3 is not OIDC compliant, so we get no id token back and userId is therefore supposed to be empty
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
    
    // Acquire token again.
    [self runSharedAuthUIAppearsStepWithTestRequest:adfsRequest];

    // Now do silent #296725
    adfsRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self runSharedSilentLoginWithTestRequest:adfsRequest];
    
    // Now do silent #296725 without providing user ID
    adfsRequest.legacyAccountIdentifier = nil;
    [self runSharedSilentLoginWithTestRequest:adfsRequest];
}

// #290995 iteration 12
- (void)testInteractiveADFSv3Login_withPromptAlways_withLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *adfsRequest = [MSIDAutomationTestRequest new];
    adfsRequest.validateAuthority = YES;
    adfsRequest.uiBehavior = @"always";
    adfsRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:adfsRequest];
    [self acquireToken:config];
    
    [self enterADFSv3Password];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:config];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)enterADFSv3Password
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
