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
#import "XCTestCase+TextFieldTap.h"
#import "NSDictionary+ADALiOSUITests.h"
#import "MSIDAADV1IdTokenClaims.h"
#import "XCUIElement+CrossPlat.h"
#import "MSIDAutomationErrorResult.h"
#import "MSIDAutomationSuccessResult.h"
#import "MSIDAADIdTokenClaimsFactory.h"
#import "MSIDAutomationActionConstants.h"

static MSIDTestConfigurationProvider *s_confProvider;

@implementation ADALBaseUITest

+ (void)setUp
{
    [super setUp];
    NSString *confPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"conf" ofType:@"json"];
    self.class.confProvider = [[MSIDTestConfigurationProvider alloc] initWithConfigurationPath:confPath];
}

- (void)setUp
{
    [super setUp];
    
    self.continueAfterFailure = NO;
    
    self.testApp = [XCUIApplication new];
    [self.testApp launch];

    [self clearKeychain];
    [self clearCookies];
}

- (void)tearDown
{
    [self.testApp terminate];
    [super tearDown];
}

+ (MSIDTestConfigurationProvider *)confProvider
{
    return s_confProvider;
}

+ (void)setConfProvider:(MSIDTestConfigurationProvider *)confProvider
{
    s_confProvider = confProvider;
}

#pragma mark - Result helpers

- (MSIDAutomationErrorResult *)automationErrorResult
{
    MSIDAutomationErrorResult *result = [[MSIDAutomationErrorResult alloc] initWithJSONDictionary:[self automationResultDictionary] error:nil];
    XCTAssertNotNil(result);
    XCTAssertFalse(result.success);
    return result;
}

- (MSIDAutomationSuccessResult *)automationSuccessResult
{
    MSIDAutomationSuccessResult *result = [[MSIDAutomationSuccessResult alloc] initWithJSONDictionary:[self automationResultDictionary] error:nil];
    XCTAssertNotNil(result);
    XCTAssertTrue(result.success);
    return result;
}

- (NSDictionary *)automationResultDictionary
{
    XCUIElement *resultTextView = self.testApp.textViews[@"resultInfo"];
    [self waitForElement:resultTextView];
    
    NSError *error = nil;
    NSData *data = [resultTextView.value dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *result = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    return result;
}

#pragma mark - Action helpers

- (void)performAction:(NSString *)action withConfig:(NSDictionary *)config
{
    NSString *jsonString = [config toJsonString];
    [self.testApp.buttons[action] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidTap];
    [self.testApp.textViews[@"requestInfo"] msidPasteText:jsonString application:self.testApp];
    sleep(1);
    [self.testApp.buttons[@"Go"] msidTap];
}

#pragma mark - Asserts

- (void)assertRefreshTokenInvalidated
{
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    XCTAssertTrue(result.success);
}

- (void)assertAccessTokenExpired
{
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    XCTAssertTrue(result.success);
    XCTAssertEqual(result.actionCount, 1);
}

- (void)assertAuthUIAppear
{
    XCUIElement *webView = [self.testApp.webViews elementBoundByIndex:0];
    BOOL result = [webView waitForExistenceWithTimeout:2.0];
    
    XCTAssertTrue(result);
}

- (void)assertErrorCode:(NSString *)expectedErrorCode
{
    MSIDAutomationErrorResult *result = [self automationErrorResult];
    NSString *actualErrorCode = result.errorName;
    XCTAssertEqualObjects(expectedErrorCode, actualErrorCode);
}

- (void)assertErrorDescription:(NSString *)errorDescription
{
    MSIDAutomationErrorResult *result = [self automationErrorResult];
    NSString *actualContent = result.errorDescription;
    XCTAssertNotEqual([actualContent length], 0);
    XCTAssertTrue([actualContent containsString:errorDescription]);
}

- (void)assertErrorSubcode:(NSString *)errorSubcode
{
    MSIDAutomationErrorResult *result = [self automationErrorResult];
    NSString *actualSubCode = result.errorUserInfo[@"ADOAuthSubErrorKey"];
    XCTAssertEqualObjects(errorSubcode, actualSubCode);
}

- (void)assertAccessTokenNotNil
{
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    
    XCTAssertTrue([result.accessToken length] > 0);
    XCTAssertTrue(result.success);
}

- (NSDictionary *)resultIDTokenClaims
{
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    
    NSString *idToken = result.idToken;
    XCTAssertTrue([idToken length] > 0);
    
    MSIDIdTokenClaims *idTokenClaims = [MSIDAADIdTokenClaimsFactory claimsFromRawIdToken:idToken error:nil];
    return [idTokenClaims jsonDictionary];
}

- (void)assertRefreshTokenNotNil
{
    MSIDAutomationSuccessResult *result = [self automationSuccessResult];
    
    XCTAssertTrue([result.refreshToken length] > 0);
    XCTAssertTrue(result.success);
}

#pragma mark - API fetch

- (void)loadTestConfiguration:(MSIDTestAutomationConfigurationRequest *)request
{
    __block MSIDTestAutomationConfiguration *testConfig = nil;

    XCTestExpectation *expectation = [self expectationWithDescription:@"Get configuration"];

    [self.class.confProvider configurationWithRequest:request
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

    [self.class.confProvider passwordForAccount:account
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

- (void)aadEnterEmail
{
    [self aadEnterEmail:[NSString stringWithFormat:@"%@\n", self.primaryAccount.account] app:self.testApp];
}

- (void)aadEnterEmail:(NSString *)email app:(XCUIApplication *)app
{
    XCUIElement *emailTextField = [app.textFields elementBoundByIndex:0];
    [self waitForElement:emailTextField];
    if ([email isEqualToString:emailTextField.value])
    {
        return;
    }
    
    [self tapElementAndWaitForKeyboardToAppear:emailTextField app:app];
    [emailTextField selectTextWithApp:app];
    [emailTextField typeText:email];
}

- (void)aadEnterPassword
{
    [self aadEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password] app:self.testApp];
}

- (void)aadEnterPassword:(NSString *)password app:(XCUIApplication *)app
{
    // Enter password
    XCUIElement *passwordTextField = app.secureTextFields.firstMatch;
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField app:app];
    [passwordTextField typeText:password];
}

- (void)adfsEnterPassword
{
    [self adfsEnterPassword:[NSString stringWithFormat:@"%@\n", self.primaryAccount.password] app:self.testApp];
}

- (void)adfsEnterPassword:(NSString *)password app:(XCUIApplication *)app
{
    XCUIElement *passwordTextField = app.secureTextFields[@"Password"];
    [self waitForElement:passwordTextField];
    [self tapElementAndWaitForKeyboardToAppear:passwordTextField app:app];
    [passwordTextField typeText:password];
}

- (void)closeResultView
{
    [self.testApp.buttons[@"Done"] msidTap];
}

- (void)invalidateRefreshToken:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_INVALIDATE_RT_ACTION_IDENTIFIER withConfig:config];
}

- (void)expireAccessToken:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_EXPIRE_AT_ACTION_IDENTIFIER withConfig:config];
}

- (void)acquireToken:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_ACQUIRE_TOKEN_ACTION_IDENTIFIER withConfig:config];
}

- (void)acquireTokenSilent:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_ACQUIRE_TOKEN_SILENT_ACTION_IDENTIFIER withConfig:config];
}

- (void)clearKeychain
{
    [self.testApp.buttons[MSID_AUTO_CLEAR_KEYCHAIN_ACTION_IDENTIFIER] msidTap];
    [self waitForElement:self.testApp.buttons[@"Done"]];
    [self.testApp.buttons[@"Done"] msidTap];
}

- (void)clearCookies
{
    [self.testApp.buttons[MSID_AUTO_CLEAR_COOKIES_ACTION_IDENTIFIER] msidTap];
    [self waitForElement:self.testApp.buttons[@"Done"]];
    [self.testApp.buttons[@"Done"] msidTap];
}

- (void)openURL:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_OPEN_URL_ACTION_IDENTIFIER withConfig:config];
}

/*
 There seems to be some flakiness around sovereign user with login hint provided,
 where ESTS sometimes shows the username page with next button and sometimes redirects to the password page correctly. This portion of code waits for the "Next" button for 10 seconds if it appears.
 */
- (void)blackForestWaitForNextButton:(XCUIApplication *)application
{
    XCUIElement *emailTextField = application.textFields[@"Enter your email, phone, or Skype."];

    for (int i = 0; i < 10; i++)
    {
        if (emailTextField.exists)
        {
            [application.buttons[@"Next"] msidTap];
            break;
        }
        else
        {
            sleep(1);
        }
    }
}

- (void)closeAuthUI
{
#if TARGET_OS_IPHONE
    [[self.testApp.navigationBars elementBoundByIndex:0].buttons[@"Cancel"] msidTap];
#else
    [self.testApp.windows[@"MSID_SIGN_IN_WINDOW"].buttons[XCUIIdentifierCloseWindow] click];
#endif
}

- (void)acquireTokenWithRefreshToken:(NSDictionary *)config
{
    [self performAction:MSID_AUTO_ACQUIRE_TOKEN_WITH_RT_IDENTIFIER withConfig:config];
}

#pragma mark - Helpers

- (void)waitForElement:(id)object
{
    NSPredicate *existsPredicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    [self expectationForPredicate:existsPredicate evaluatedWithObject:object handler:nil];
    [self waitForExpectationsWithTimeout:60.0f handler:nil];
}

- (NSDictionary *)configWithTestRequest:(MSIDAutomationTestRequest *)request
{
    MSIDAutomationTestRequest *updatedRequest = [self.class.confProvider fillDefaultRequestParams:request config:self.testConfiguration account:self.primaryAccount];
    return updatedRequest.jsonDictionary;
}

#pragma mark - Shared steps

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

- (void)runSharedSilentLoginWithTestRequest:(MSIDAutomationTestRequest *)request
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

@end
