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
#import "XCUIElement+CrossPlat.h"

@interface ADALPingInteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALPingInteractiveLoginTests

- (void)setUp
{
    [super setUp];

    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderPing;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 9
- (void)testInteractivePingLogin_withPromptAlways_noLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *pingRequest = [self.class.confProvider defaultAppRequest];
    pingRequest.promptBehavior = @"always";
    
    NSDictionary *config = [self configWithTestRequest:pingRequest];
    [self acquireToken:config];
    
    [self aadEnterEmail];
    
    [self pingEnterUsername];
    [self pingEnterPassword];
    
    NSString *userId = [self runSharedResultAssertionWithTestRequest:pingRequest];
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
    
    // Acquire token again.
    [self runSharedAuthUIAppearsStepWithTestRequest:pingRequest];
}



// #290995 iteration 10
- (void)testInteractivePingLogin_withPromptAlways_withLoginHint_ADALWebView
{
    MSIDAutomationTestRequest *pingRequest = [self.class.confProvider defaultAppRequest];
    pingRequest.promptBehavior = @"always";
    pingRequest.loginHint = self.primaryAccount.account;
    
    NSDictionary *config = [self configWithTestRequest:pingRequest];
    [self acquireToken:config];
    
    [self pingEnterUsername];
    [self pingEnterPassword];
    
    NSString *userId = [self runSharedResultAssertionWithTestRequest:pingRequest];
    XCTAssertEqualObjects(userId, self.primaryAccount.account.lowercaseString);
    [self closeResultView];
    
    pingRequest.legacyAccountIdentifier = self.primaryAccount.account;
    [self runSharedSilentLoginWithTestRequest:pingRequest];
}

#pragma mark - Private

- (void)pingEnterUsername
{
    XCUIElement *usernameTextField = self.testApp.textFields.element;
    
    [self waitForElement:usernameTextField];
    [self tapElementAndWaitForKeyboardToAppear:usernameTextField];
    [usernameTextField activateTextField];
    [usernameTextField typeText:self.primaryAccount.username];
}

- (void)pingEnterPassword
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields.element;
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField];
    [passwordTextField activateTextField];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}


@end
