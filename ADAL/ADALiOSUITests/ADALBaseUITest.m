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
#import "NSDictionary+ADALiOSUITests.h"
#import "MSIDTestAutomationConfigurationRequest.h"
#import "MSIDTestAccountsProvider.h"
#import "XCTestCase+TextFieldTap.h"
#import "NSDictionary+ADALiOSUITests.h"
#import "MSIDAADV1IdTokenClaims.h"

@implementation ADALBaseUITest

- (void)setUp
{
    [super setUp];
    
    self.continueAfterFailure = NO;
    
    self.testApp = [XCUIApplication new];
    [self.testApp launch];

    [self clearKeychain];
    [self clearCookies];

    NSString *confPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"conf" ofType:@"json"];
    self.accountsProvider = [[MSIDTestAccountsProvider alloc] initWithConfigurationPath:confPath];
}

#pragma mark - Asserts

- (void)assertRefreshTokenInvalidated
{
    NSDictionary *result = [self resultDictionary];
    
    XCTAssertTrue([result[@"invalidated_refresh_token_count"] intValue] == 1);
}

- (void)assertAccessTokenExpired
{
    NSDictionary *result = [self resultDictionary];
    
    XCTAssertTrue([result[@"expired_access_token_count"] intValue] == 1);
}

- (void)assertAuthUIAppear
{
    XCUIElement *webView = self.testApp.otherElements[@"ADAL_SIGN_IN_WEBVIEW"].firstMatch;
    
    BOOL result = [webView waitForExistenceWithTimeout:2.0];
    
    XCTAssertTrue(result);
}

- (void)assertError:(NSString *)error
{
    NSDictionary *result = [self resultDictionary];
    
    XCTAssertNotEqual([result[@"error"] length], 0);
    NSString *errorDescription = result[@"error_description"];
    XCTAssertTrue([errorDescription containsString:error]);
}

- (void)assertAccessTokenNotNil
{
    NSDictionary *result = [self resultDictionary];
    
    XCTAssertTrue([result[@"access_token"] length] > 0);
    XCTAssertEqual([result[@"error"] length], 0);
}

- (NSDictionary *)resultIDTokenClaims
{
    NSDictionary *result = [self resultDictionary];

    NSString *idToken = result[@"id_token"];
    XCTAssertTrue([idToken length] > 0);

    MSIDAADV1IdTokenClaims *idTokenWrapper = [[MSIDAADV1IdTokenClaims alloc] initWithRawIdToken:idToken error:nil];
    return [idTokenWrapper jsonDictionary];
}

- (void)assertRefreshTokenNotNil
{
    NSDictionary *result = [self resultDictionary];
    
    XCTAssertTrue([result[@"refresh_token"] length] > 0);
}

#pragma mark - API fetch

- (void)loadTestConfiguration:(MSIDTestAutomationConfigurationRequest *)request
{
    __block MSIDTestAutomationConfiguration *testConfig = nil;

    XCTestExpectation *expectation = [self expectationWithDescription:@"Get configuration"];

    [self.accountsProvider configurationWithRequest:request
                                  completionHandler:^(MSIDTestAutomationConfiguration *configuration) {

                                      testConfig = configuration;
                                      [expectation fulfill];
                                  }];

    [self waitForExpectationsWithTimeout:60 handler:nil];

    if (!testConfig || ![testConfig.accounts count])
    {
        XCTAssertTrue(NO);
    }

    [self loadPasswordForAccount:testConfig.accounts[0]];

    self.testConfiguration = testConfig;
    XCTAssertTrue([self.testConfiguration.accounts count] >= 1);
    self.primaryAccount = self.testConfiguration.accounts[0];
}

- (void)loadPasswordForAccount:(MSIDTestAccount *)account
{
    XCTestExpectation *expectation = [self expectationWithDescription:@"Get password"];

    [self.accountsProvider passwordForAccount:account
                            completionHandler:^(NSString *password) {
                                [expectation fulfill];
                            }];

    [self waitForExpectationsWithTimeout:60 handler:nil];

    if (!account.password)
    {
        XCTAssertTrue(NO);
    }
}

#pragma mark - Actions

- (void)aadEnterEmail:(NSString *)email
{
    XCUIElement *emailTextField = self.testApp.textFields[@"Email, phone, or Skype"];
    [self waitForElement:emailTextField];
    if ([email isEqualToString:emailTextField.value])
    {
        return;
    }

    [self tapElementAndWaitForKeyboardToAppear:emailTextField];
        
    // There is a bug when we test in iOS 11 when emailTextField.value return placeholder value
    // instead of empty string. In order to make it work we check that value of text field is not
    // equal to placeholder.
    // See here: https://forums.developer.apple.com/thread/86653
    if (![emailTextField.placeholderValue isEqualToString:emailTextField.value] && emailTextField.value)
    {
        [emailTextField selectAll:self.testApp];
    }
    [emailTextField typeText:email];
}

- (void)aadEnterEmail
{
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", self.primaryAccount.account]];
}

- (void)aadEnterPassword
{
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password]];
}

- (void)aadEnterPasswordInApp:(XCUIApplication *)app
{
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password] testApp:app];
}

- (void)aadEnterPassword:(NSString *)password
{
    [self aadEnterPassword:password testApp:self.testApp];
}

- (void)aadEnterPassword:(NSString *)password testApp:(XCUIApplication *)testApp
{
    XCUIElement *passwordTextField = testApp.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField app:testApp];
    [passwordTextField typeText:password];
}

- (void)closeAuthUI
{
     [self.testApp.navigationBars[@"ADAuthenticationView"].buttons[@"Cancel"] tap];
}

- (void)closeResultView
{
    [self.testApp.buttons[@"Done"] tap];
}

- (void)invalidateRefreshToken:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[@"Invalidate Refresh Token"] tap];
    [self.testApp.textViews[@"requestInfo"] tap];
    [self.testApp.textViews[@"requestInfo"] pasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
}

- (void)expireAccessToken:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[@"Expire Access Token"] tap];
    [self.testApp.textViews[@"requestInfo"] tap];
    [self.testApp.textViews[@"requestInfo"] pasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
}

- (void)acquireToken:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[@"Acquire Token"] tap];
    [self.testApp.textViews[@"requestInfo"] tap];
    [self.testApp.textViews[@"requestInfo"] pasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
}

- (void)acquireTokenSilent:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[@"Acquire Token Silent"] tap];
    [self.testApp.textViews[@"requestInfo"] tap];
    [self.testApp.textViews[@"requestInfo"] pasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
}

- (void)clearCache
{
    [self.testApp.buttons[@"Clear Cache"] tap];
    [self.testApp.buttons[@"Done"] tap];
}

- (void)clearKeychain
{
    [self.testApp.buttons[@"Clear keychain"] tap];
    [self.testApp.buttons[@"Done"] tap];
}

- (void)clearCookies
{
    [self.testApp.buttons[@"Clear Cookies"] tap];
    [self.testApp.buttons[@"Done"] tap];
}

- (void)openURL:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[@"openUrlInSafari"] tap];
    [self.testApp.textViews[@"requestInfo"] tap];
    [self.testApp.textViews[@"requestInfo"] pasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] tap];
}

#pragma mark - Helpers

- (NSDictionary *)resultDictionary
{
    XCUIElement *resultTextView = self.testApp.textViews[@"resultInfo"];
    [self waitForElement:resultTextView];
    
    return [NSJSONSerialization JSONObjectWithData:[resultTextView.value dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
}

- (void)waitForElement:(id)object
{
    NSPredicate *existsPredicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    [self expectationForPredicate:existsPredicate evaluatedWithObject:object handler:nil];
    [self waitForExpectationsWithTimeout:60.0f handler:nil];
}

#pragma mark - Multi app

- (void)openAppInstallURLForAppId:(NSString *)appId
{
    XCTAssertNotNil(appId);

    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:appId];
    XCTAssertNotNil(appConfiguration);

    NSString *appInstallUrl = appConfiguration[@"install_url"];

    NSDictionary *dictionary = @{@"safari_url": appInstallUrl};
    [self openURL:dictionary];

    XCUIApplication *safariApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.mobilesafari"];

    XCTAssertTrue([safariApp waitForState:XCUIApplicationStateRunningForeground timeout:30]);
    [safariApp tap];
}

- (void)allowNotificationsInSystemAlert
{
    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    __auto_type allowButton = springBoardApp.alerts.buttons[@"Allow"];
    [self waitForElement:allowButton];
    [allowButton tap];
}

- (void)waitForRedirectToTheTestApp
{
    BOOL result = [self.testApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);
}

- (XCUIApplication *)installAppWithId:(NSString *)appId
{
    /* Because for certain tests we want to install app after running some preliminary operations,
     we split the operation into 2 parts: opening the install URL in Safari and actually installing the app */
    [self openAppInstallURLForAppId:appId];
    return [self installAppWithIdWithSafariOpen:appId];
}

- (XCUIApplication *)installAppWithIdWithSafariOpen:(NSString *)appId
{
    XCUIApplication *safariApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.mobilesafari"];
    [safariApp activate];

    XCTAssertTrue([safariApp waitForState:XCUIApplicationStateRunningForeground timeout:30]);
    [safariApp tap];
    __auto_type installButton = safariApp.links[@"Install"];
    [self waitForElement:installButton];
    [installButton tap];

    sleep(1);

    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    [springBoardApp.alerts.buttons[@"Install"] tap];

    [springBoardApp activate];
    BOOL result = [springBoardApp waitForState:XCUIApplicationStateRunningForeground timeout:30];
    XCTAssertTrue(result);

    sleep(3);

    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:appId];
    NSString *appName = appConfiguration[@"app_name"];

    __auto_type appIcon = springBoardApp.icons[appName];
    [self waitForElement:appIcon];
    [appIcon tap];

    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *installedApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    // Give app enough time to install
    result = [installedApp waitForState:XCUIApplicationStateRunningForeground timeout:60];
    XCTAssertTrue(result);

    return installedApp;
}

- (void)removeAppWithId:(NSString *)appId
{
    XCTAssertNotNil(appId);

    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:appId];
    XCTAssertNotNil(appConfiguration);

    XCUIApplication *springBoardApp = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    [springBoardApp activate];
    BOOL result = [springBoardApp waitForState:XCUIApplicationStateRunningForeground timeout:30];
    XCTAssertTrue(result);

    NSString *appName = appConfiguration[@"app_name"];

    __auto_type appIcon = springBoardApp.icons[appName];

    if (appIcon.exists)
    {
        [appIcon pressForDuration:1.0f];
        [appIcon.buttons[@"DeleteButton"] tap];

        __auto_type deleteButton = springBoardApp.alerts.buttons[@"Delete"];
        [self waitForElement:deleteButton];
        [deleteButton tap];

        NSPredicate *appDeletedPredicate = [NSPredicate predicateWithFormat:@"exists == 0"];
        [self expectationForPredicate:appDeletedPredicate evaluatedWithObject:appIcon handler:nil];
        [self waitForExpectationsWithTimeout:30 handler:nil];

        [[XCUIDevice sharedDevice] pressButton:XCUIDeviceButtonHome];
    }
}

#pragma mark - Broker

- (XCUIApplication *)brokerApp
{
    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:@"broker"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];

    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    BOOL result = [brokerApp waitForState:XCUIApplicationStateRunningForeground timeout:30.0f];
    XCTAssertTrue(result);

    if ([brokerApp.alerts.buttons[@"Ok"] exists])
    {
        [brokerApp.alerts.buttons[@"Ok"] tap];
    }

    return brokerApp;
}

- (void)registerDeviceInAuthenticator
{
    NSDictionary *appConfiguration = [self.accountsProvider appInstallForConfiguration:@"broker"];
    NSString *appBundleId = appConfiguration[@"app_bundle_id"];
    XCUIApplication *brokerApp = [[XCUIApplication alloc] initWithBundleIdentifier:appBundleId];
    [brokerApp terminate];
    [brokerApp activate];

    if ([brokerApp.buttons[@"Skip"] exists])
    {
        [brokerApp.buttons[@"Skip"] tap];
    }

    [brokerApp.navigationBars[@"Accounts"].buttons[@"Menu"] tap];

    __auto_type settingsMenuItem = brokerApp.tables.staticTexts[@"Settings"];
    [self waitForElement:settingsMenuItem];
    [settingsMenuItem tap];

    __auto_type emailTextField = brokerApp.tables.textFields[@"Organization email"];
    [self tapElementAndWaitForKeyboardToAppear:emailTextField app:brokerApp];
    [emailTextField typeText:[NSString stringWithFormat:@"%@\n", self.primaryAccount.account]];

    __auto_type registerButton = brokerApp.tables.buttons[@"Register device"];
    [registerButton tap];

    [self aadEnterPasswordInApp:brokerApp];
}

@end
