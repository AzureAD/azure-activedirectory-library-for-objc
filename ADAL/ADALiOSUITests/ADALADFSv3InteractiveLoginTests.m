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

@interface ADALADFSv3InteractiveLoginTests : ADALBaseUITest

@end

@implementation ADALADFSv3InteractiveLoginTests

- (void)setUp
{
    [super setUp];
    
    [self clearCache];
    [self clearCookies];

    ADTestConfigurationRequest *configurationRequest = [ADTestConfigurationRequest new];
    configurationRequest.accountProvider = ADTestAccountProviderAdfsv3;
    configurationRequest.testApplication = ADTestApplicationCloud;
    configurationRequest.appVersion = ADAppVersionV1;
    [self loadTestConfiguration:configurationRequest];
}

#pragma mark - Tests

// #290995 iteration 11
- (void)testInteractiveADFSv3Login_withPromptAlways_noLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707", // TODO: remove me once non CA accounts are available
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive", // TODO: remove me once non CA accounts are available,
                             @"resource": @"01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" // TODO: remove me once non CA accounts are available,
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self aadEnterEmail];
    [self enterADFSv3Password];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

// #290995 iteration 12
- (void)testInteractiveADFSv3Login_withPromptAlways_withLoginHint_ADALWebView
{
    NSDictionary *params = @{
                             @"prompt_behavior" : @"always",
                             @"validate_authority" : @YES,
                             @"user_identifier" : self.primaryAccount.account,
                             @"user_identifier_type" : @"optional_displayable",
                             @"client_id": @"af124e86-4e96-495a-b70a-90f90ab96707", // TODO: remove me once non CA accounts are available
                             @"redirect_uri": @"ms-onedrive://com.microsoft.skydrive", // TODO: remove me once non CA accounts are available,
                             @"resource": @"01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" // TODO: remove me once non CA accounts are available
                             };
    NSString *configJson = [[self.testConfiguration configParametersWithAdditionalParams:params] toJsonString];
    
    [self acquireToken:configJson];
    
    [self enterADFSv3Password];
    
    [self assertAccessTokenNotNil];
    [self closeResultView];
    
    // Acquire token again.
    [self acquireToken:configJson];
    [self assertAuthUIAppear];
}

#pragma mark - Private

- (void)enterADFSv3Password
{
    XCUIElement *passwordTextField = self.testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [passwordTextField pressForDuration:0.5f];
    [passwordTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

@end
