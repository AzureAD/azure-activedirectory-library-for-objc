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
#import "ADTelemetryTestDispatcher.h"
#import "ADTelemetry.h"
#import "ADKeychainTokenCache.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCacheItem.h"
#import "ADKeychainTokenCache+Internal.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTokenCache.h"
#import "ADAuthorityValidation.h"
#import "ADAuthenticationContext+TestUtil.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"

@interface ADWipeTokensTelemetryTests : ADTestCase

@end

@implementation ADWipeTokensTelemetryTests

- (void)setUp
{
    [super setUp];
    
    [MSIDKeychainTokenCache reset];
}

- (void)tearDown
{
    [super tearDown];
    
    [MSIDKeychainTokenCache reset];
}

- (void)testWipeAllItemsForUserId_withOneItem_shouldGenerateTelemetry
{
    // Setup telemetry callback
    ADTelemetryTestDispatcher *dispatcher = [ADTelemetryTestDispatcher new];
    
    NSMutableArray *receivedEvents = [NSMutableArray array];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSDictionary *event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] addDispatcher:dispatcher aggregationRequired:YES];
    
    // Add test tokens to cache
    NSError *error = nil;
    
    ADKeychainTokenCache *store = [[ADKeychainTokenCache alloc] init];
    
    ADTokenCacheItem *item1 = [self adCreateCacheItem:@"eric@contoso.com"];
    [item1 setClientId:@"client 1"];
    [store addOrUpdateItem:item1 correlationId:nil error:&error];
    
    XCTAssertNil(error);
    
    //remove items with user ID as @"eric@contoso.com" and client ID as TEST_CLIENT_ID
    XCTAssertTrue([store wipeAllItemsForUserId:@"eric@contoso.com" error:&error]);
    XCTAssertNil(error);
    
    ADAuthenticationContext *context = [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                                                        validateAuthority:NO
                                                                                    error:nil];
    
//    context.tokenCache = [MSIDSharedTokenCache new];
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    [[ADAuthorityValidation sharedInstance] addInvalidAuthority:TEST_AUTHORITY];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    // Run acquireTokenSilent, simulating an app trying to find a token and not finding
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
     {
         XCTAssertNotNil(result);
         XCTAssertEqual(result.status, AD_FAILED);
         XCTAssertNotNil(result.error);
         XCTAssertEqual(result.error.code, AD_ERROR_SERVER_USER_INPUT_NEEDED);
         XCTAssertNil(result.authority);
         
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // Test that telemetry got generated
    XCTAssertEqual([receivedEvents count], 1);
    
    NSDictionary *event = [receivedEvents firstObject];
    XCTAssertEqualObjects(event[@"Microsoft.ADAL.wipe_app"], @"com.microsoft.unittesthost");
    XCTAssertNotNil(event[@"Microsoft.ADAL.wipe_time"]);
}

@end

