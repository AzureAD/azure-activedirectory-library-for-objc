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

#define DEFAULT_AAD_USERNAME @"user@msdevex.onmicrosoft.com"
#define DEFAULT_AAD_PASSWORD @"wordp@ss1"

#define DEFAULT_SHIB_USERNAME @"aduser1@msidlab13.com"
#define DEFAULT_SHIB_USERID @"aduser1"
#define DEFAULT_SHIB_PASSWORD @"Hulu@135"

#define DEFAULT_PING_USERNAME @"atoster@ektd.pingdemo.com"
#define DEFAULT_PING_USERID @"atoster"
#define DEFAULT_PING_PASSWORD @"For7una!"

#define DEFAULT_BLACKFOREST_USERNAME @"TestSovereign@bfe2e.onmicrosoft.de"
#define DEFAULT_BLACKFOREST_PASSWORD @"P@ssw0rd!"

@interface ADALBaseTest : XCTestCase
{
    XCUIApplication *_testApplication;
}

// Actions
- (void)launchTestAppWithDefaultTab;
- (void)acquireToken;
- (void)acquireTokenSilent;
- (void)startAndCancelInteractiveSignin;

// Options
- (void)selectProfile:(NSString *)profile;
- (void)selectWebViewType:(NSString *)webViewType;
- (void)selectPromptBehavior:(NSString *)promptType;
- (void)selectUserIdType:(NSString *)userIdType;
- (void)selectBrokerAuthType:(NSString *)brokerAuthType;
- (void)selectAuthorityValidationType:(NSString *)authorityValidationType;
- (void)selectTab:(NSString *)tab;

// Fields
- (void)enterUserId:(NSString *)userId;
- (void)enterEQP:(NSString *)eqp;

// Helpers
- (NSString *)readResult;
- (void)waitForTokenResultWithCompletionHandler:(void (^)(NSDictionary *result))completion;

// Buttons
- (void)clearCache;
- (void)clearCookies;
- (void)wipeCacheForUserId:(NSString *)userId;

// WebView
- (void)enterAADUsername:(NSString *)username;
- (void)waitForAADLoginPage;
- (void)waitForAADRedirrect;

@end
