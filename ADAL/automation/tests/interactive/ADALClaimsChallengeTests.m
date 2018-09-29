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

@interface ADALClaimsChallengeTests : ADALBaseUITest

@end

@implementation ADALClaimsChallengeTests

- (void)setUp
{
    [super setUp];
}

- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_withMAMCAClaims_withPassedInWebview
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];

    NSDictionary *params = @{
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"web_view" : @"passed_in",
                             };

    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];

    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];

    params = @{
               @"user_identifier" : self.primaryAccount.account,
               @"claims": @"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D",
               @"web_view" : @"passed_in",
               };

    config = [self.testConfiguration configWithAdditionalConfiguration:params];

    // Acquire token again.
    [self acquireToken:config];

    XCUIElement *getAppButton = self.testApp.buttons[@"Get the app"];
    [self waitForElement:getAppButton];
}

- (void)testInteractiveAADLogin_withPromptAuto_withLoginHint_withMAMCAClaims_withADALWebview
{
    MSIDTestAutomationConfigurationRequest *configurationRequest = [MSIDTestAutomationConfigurationRequest new];
    configurationRequest.accountProvider = MSIDTestAccountProviderWW;
    configurationRequest.appVersion = MSIDAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
    
    NSDictionary *params = @{
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             };
    
    NSDictionary *config = [self.testConfiguration configWithAdditionalConfiguration:params];
    [self acquireToken:config];
    
    [self aadEnterPassword];
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    params = @{
               @"user_identifier" : self.primaryAccount.account,
               @"claims": @"%7B%22access_token%22%3A%7B%22deviceid%22%3A%7B%22essential%22%3Atrue%7D%7D%7D",
               };
    
    config = [self.testConfiguration configWithAdditionalConfiguration:params];
    
    // Acquire token again.
    [self acquireToken:config];
    
    XCUIElement *getAppButton = self.testApp.buttons[@"Get the app"];
    [self waitForElement:getAppButton];
}

@end
