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

#import "ADALBaseTest.h"

/*!
 Any shared helpers for UI tests should be in the base class
 */
@implementation ADALBaseTest

- (void)setUp
{
    [super setUp];
    self.continueAfterFailure = NO;
    // Because UI tests target test app, it will be the default app to be picked
    _testApplication = [[XCUIApplication alloc] init];
}

#pragma mark - Actions

- (void)launchTestAppWithDefaultTab
{
    [_testApplication launch];
    [self selectTab:@"Acquire"];
}

- (void)acquireToken
{
    [_testApplication.buttons[@"acquire_token_btn"] tap];
}

- (void)acquireTokenSilent
{
    [_testApplication.buttons[@"acquire_token_silent_btn"] tap];
}

- (void)startAndCancelInteractiveSignin
{
    [self acquireToken];
    [_testApplication.navigationBars[@"ADAuthenticationView"].buttons[@"Cancel"] tap];
}

#pragma mark - Options

- (void)selectProfile:(NSString *)profile
{
    [_testApplication.scrollViews.otherElements.buttons[@"profile_button"] tap];
    [_testApplication.tables.staticTexts[profile] tap];
}

- (void)selectSegmentedControlOption:(NSString *)controlName option:(NSString *)option
{
    XCUIElement *control = _testApplication.scrollViews.otherElements.segmentedControls[controlName];
    [control.buttons[option] tap];
}

- (void)selectWebViewType:(NSString *)webViewType
{
    [self selectSegmentedControlOption:@"webview_type_control" option:webViewType];
}

- (void)selectPromptBehavior:(NSString *)promptType
{
    [self selectSegmentedControlOption:@"prompt_type_control" option:promptType];
}

- (void)selectUserIdType:(NSString *)userIdType
{
    [self selectSegmentedControlOption:@"user_id_control" option:userIdType];
}

- (void)selectBrokerAuthType:(NSString *)brokerAuthType
{
    [self selectSegmentedControlOption:@"broker_auth_type" option:brokerAuthType];
}

- (void)selectAuthorityValidationType:(NSString *)authorityValidationType
{
    [self selectSegmentedControlOption:@"validate_authority_type" option:authorityValidationType];
}

- (void)selectTab:(NSString *)tab
{
    [_testApplication.tabBars.buttons[tab] tap];
}

#pragma mark - Fields

- (void)clearTextField:(XCUIElement *)element
{
    [element tap];
    
    NSString *clearText = @"";
    NSString *elementText = element.value;
    
    for (int i = 0; i < [elementText length]; i++)
    {
        clearText = [clearText stringByAppendingString:XCUIKeyboardKeyDelete];
    }
    
    [element typeText:clearText];
}

- (void)enterUserId:(NSString *)userId
{
    XCUIElement *userIdField = _testApplication.scrollViews.otherElements.textFields[@"user_id_field"];
    
    [self clearTextField:userIdField];
    [userIdField tap];
    [userIdField typeText:userId];
}

- (void)enterEQP:(NSString *)eqp
{
    XCUIElement *eqpField = _testApplication.scrollViews.otherElements.textFields[@"eqp_field"];
    [self clearTextField:eqpField];
    [eqpField tap];
    [eqpField typeText:eqp];
}

#pragma mark - Buttons

- (void)clearCache
{
    [_testApplication.scrollViews.otherElements.buttons[@"clear_cache"] tap];
    NSString *result = [self readResult];
    XCTAssertEqualObjects(result, @"Successfully cleared cache.");
}

- (void)clearCookies
{
    [_testApplication.scrollViews.otherElements.buttons[@"clear_cookies"] tap];
    NSString *result = [self readResult];
    
    // We don't care how many cookies we cleared
    XCTAssertTrue([result hasPrefix:@"Cleared"]
                  && [result hasSuffix:@"cookies."]);
}

- (void)wipeCacheForUserId:(NSString *)userId
{
    [self enterUserId:userId];
    [_testApplication.scrollViews.otherElements.buttons[@"wipe_cache_for_upn"] tap];
    NSString *result = [self readResult];
    NSString *expected = [NSString stringWithFormat:@"Wiped cache for %@.", userId];
    XCTAssertEqualObjects(result, expected);
}

#pragma mark - Helpers

- (NSString *)readResult
{
    XCUIElement *resultView = _testApplication.scrollViews.otherElements.textViews[@"result_view"];
    return resultView.value;
}

- (void)waitForTokenResultWithCompletionHandler:(void (^)(NSDictionary *result))completion
{
    XCUIElement *resultView = _testApplication.scrollViews.otherElements.textViews[@"result_view"];
    
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"value CONTAINS[cd] %@", @"status"];
    [self expectationForPredicate:predicate evaluatedWithObject:resultView handler:nil];
    
    [self waitForExpectationsWithTimeout:20.0f handler:^(NSError * _Nullable error) {
        
        if (!error)
        {
            NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:[resultView.value dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
            
            if (completion)
            {
                completion(dictionary);
            }
        }
        else if (completion)
        {
            completion(nil);
        }
    }];
}

#pragma mark - WebView

- (void)enterAADUsername:(NSString *)username
{
    // Wait for AAD username page to load
    [self waitForAADLoginPage];
    
    // Enter the username
    XCUIElement *emailTextField = _testApplication.webViews.textFields[@"Email or phone"];
    [emailTextField pressForDuration:0.5f];
    [emailTextField typeText:username];
    
    // Press next
    XCUIElement *nextButton = _testApplication.webViews.buttons[@"Next"];
    [nextButton tap];
}

- (void)waitForAADLoginPage
{
    XCUIElementQuery *webViewsQuery = _testApplication.webViews;
    XCUIElement *emailOrPhoneTextField = webViewsQuery.textFields[@"Email or phone"];
    
    NSPredicate *predicate = [NSPredicate predicateWithFormat:@"exists == 1"];
    
    [self expectationForPredicate:predicate
              evaluatedWithObject:emailOrPhoneTextField handler:nil];
    [self waitForExpectationsWithTimeout:20.0f handler:nil];
}

- (void)waitForAADRedirrect
{
    XCUIElement *redirrectText = _testApplication.staticTexts[@"Taking you to your organization's sign-in page"];
    [self expectationForPredicate:[NSPredicate predicateWithFormat:@"exists == 1"]
              evaluatedWithObject:redirrectText
                          handler:nil];
    [self waitForExpectationsWithTimeout:20.0f handler:nil];
}

@end
