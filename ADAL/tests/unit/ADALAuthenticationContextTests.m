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

#import "ADALAuthenticationContextTests.h"
#import "ADALAuthenticationContext+Internal.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADALErrorCodes.h"
#import "ADALTokenCache+Internal.h"
#import "ADALTokenCacheItem+Internal.h"
#import "ADALUserIdentifier.h"
#import "ADALAuthenticationRequest.h"
#import "ADALAuthenticationRequest+Broker.h"
#if TARGET_OS_IPHONE
#import "ADALBrokerNotificationManager.h"
#endif

@implementation ADALAuthenticationContextTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
    
#if TARGET_OS_IPHONE
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kAdalResumeDictionaryKey];
    [[ADALBrokerNotificationManager sharedInstance] copyAndClearCallback];
#endif
}

#pragma mark - Initialization

- (void)testNew_shouldThrow
{
    XCTAssertThrows([ADALAuthenticationContext new], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

- (void)testParameterlessInit_shouldThrow
{
    XCTAssertThrows([[ADALAuthenticationContext alloc] init], @"The new selector should not work due to requirement to use the parameterless init. At: '%s'", __PRETTY_FUNCTION__);
}

#pragma mark - authenticationContextWithAuthority

- (void)testAuthenticationContextWithAuthority_whenAuthorityNil_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADALAuthenticationContext authenticationContextWithAuthority:authority error:&error];
    
    XCTAssertNil(context);
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityNilValidatedAuthorityNo_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    NSString *authority = nil;
    context = [ADALAuthenticationContext authenticationContextWithAuthority:authority validateAuthority:NO error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlank_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:@"   " error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityBlankValidateAuthorityNo_shouldReturnErrorAndNilContext
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:@"   " validateAuthority:NO error:&error];
    
    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, AD_ERROR_DEVELOPER_INVALID_ARGUMENT);
    ADTAssertContains(error.errorDetails, @"authority");
    XCTAssertNil(context);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValid_shouldReturnContextAndNilError
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

- (void)testAuthenticationContextWithAuthority_whenAuthorityIsValidValidateAuthorityNo_shouldReturnContextAndNilError
{
    ADALAuthenticationContext *context = nil;
    ADALAuthenticationError *error = nil;
    
    context = [ADALAuthenticationContext authenticationContextWithAuthority:TEST_AUTHORITY validateAuthority:NO error:&error];
    
    XCTAssertNotNil(context);
    XCTAssertEqualObjects(context.authority, TEST_AUTHORITY);
    XCTAssertNil(error);
}

#if TARGET_OS_IPHONE

- (void)testCanHandleResponse_whenProtocolVersionIs2AndRequestIntiatedByAdal_shouldReturnYes
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey: kAdalSDKObjc};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertTrue(result);
}

- (void)testCanHandleResponse_whenProtocolVersionIs2AndRequestIsNotIntiatedByAdal_shouldReturnNo
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey: @"msal-objc"};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

- (void)testCanHandleResponse_whenProtocolVersionIs2AndThereIsNoCallbackAndNoResumeDictionary_shouldReturnNo
{
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

- (void)testCanHandleResponse_whenProtocolVersionIs2AndThereIsCallbackAndNoResumeDictionary_shouldReturnYes
{
    [[ADALBrokerNotificationManager sharedInstance] enableNotifications:^(__unused ADALAuthenticationResult *result) { }];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertTrue(result);
}

- (void)testCanHandleResponse_whenProtocolVersionIs3AndRequestIntiatedByAdal_shouldReturnNo
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey: kAdalSDKObjc};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=3&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

- (void)testCanHandleResponse_whenNotFromBroker_shouldReturnNo
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey: kAdalSDKObjc};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=3&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.notbroker";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

- (void)testCanHandleResponse_whenSourceApplicationNil_shouldStillReturnYes
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey: kAdalSDKObjc};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=3&response=someEncryptedResponse"];
    NSString *sourceApp = nil;
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

- (void)testCanHandleResponse_whenNotMatchRedirectUri_shouldReturnNo
{
    NSDictionary *resumeDictionary = @{kAdalSDKNameKey : kAdalSDKObjc, @"redirect_uri" : @"different://redirect.uri"};
    [[NSUserDefaults standardUserDefaults] setObject:resumeDictionary forKey:kAdalResumeDictionaryKey];
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

#else

- (void)testCanHandleResponse_shouldReturnNo
{
    NSURL *url = [[NSURL alloc] initWithString:@"testapp://com.microsoft.testapp/broker?msg_protocol_ver=2&response=someEncryptedResponse"];
    NSString *sourceApp = @"com.microsoft.azureauthenticator";
    
    BOOL result = [ADALAuthenticationContext canHandleResponse:url sourceApplication:sourceApp];
    
    XCTAssertFalse(result);
}

#endif

@end
