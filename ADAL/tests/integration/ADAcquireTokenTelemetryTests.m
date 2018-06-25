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
#import "XCTestCase+TestHelperMethods.h"
#import "ADTestURLSession.h"
#import "ADTestURLResponse.h"
#import "ADTelemetryTestDispatcher.h"
#import "ADAuthorityValidation.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "MSIDLegacyTokenCacheAccessor.h"
#import "ADAuthenticationContext+TestUtil.h"
#import "MSIDDeviceId.h"
#import "ADTokenCacheKey.h"
#import "NSString+MSIDExtensions.h"
#import "MSIDTelemetryEventStrings.h"
#import "MSIDAADV1Oauth2Factory.h"

#if TARGET_OS_IPHONE
#import "MSIDKeychainTokenCache+MSIDTestsUtil.h"
#import "MSIDKeychainTokenCache.h"
#import "ADLegacyKeychainTokenCache.h"
#else
#import "ADTokenCache+Internal.h"
#endif

@interface ADAcquireTokenTelemetryTests : ADTestCase

@property (nonatomic) MSIDLegacyTokenCacheAccessor *tokenCache;
@property (nonatomic) id<ADTokenCacheDataSource> cacheDataSource;
@property (nonatomic) NSMutableArray *receivedEvents;

@end

@implementation ADAcquireTokenTelemetryTests

- (void)setUp
{
    [super setUp];
    
    _receivedEvents = [NSMutableArray array];
    [self resetCache];
}

- (void)tearDown
{
    [super tearDown];
    
    [[ADTelemetry sharedInstance] removeAllDispatchers];
    [ADTelemetry sharedInstance].piiEnabled = NO;
}

- (void)resetCache
{
#if TARGET_OS_IPHONE
    [MSIDKeychainTokenCache reset];
    
    self.cacheDataSource = ADLegacyKeychainTokenCache.defaultKeychainCache;
    self.tokenCache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:MSIDKeychainTokenCache.defaultKeychainCache otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
#else
    ADTokenCache *adTokenCache = [ADTokenCache new];
    self.cacheDataSource = adTokenCache;
    self.tokenCache = [[MSIDLegacyTokenCacheAccessor alloc] initWithDataSource:adTokenCache.macTokenCache otherCacheAccessors:nil factory:[MSIDAADV1Oauth2Factory new]];
#endif
}

- (void)setupForAcquireTokenWithNetworkResponse
{
    // A simple FRT case, the only RT available is the FRT so that would should be the one used
    ADAuthenticationError *error = nil;
    XCTAssertTrue([self.cacheDataSource addOrUpdateItem:[self adCreateFRTCacheItem] correlationId:nil error:&error]);
    XCTAssertNil(error);
    
    ADTestURLResponse *response = [self adResponseRefreshToken:@"family refresh token"
                                                     authority:TEST_AUTHORITY
                                               requestResource:TEST_RESOURCE
                                              responseResource:TEST_RESOURCE                                                                          clientId:TEST_CLIENT_ID
                                                requestHeaders:nil
                                                 correlationId:TEST_CORRELATION_ID
                                               newRefreshToken:@"new family refresh token"
                                                newAccessToken:TEST_ACCESS_TOKEN
                                                    newIDToken:[self adDefaultIDToken]
                                              additionalFields:@{ ADAL_CLIENT_FAMILY_ID : @"1"}
                                               responseHeaders:@{@"x-ms-clitelem" : @"1,0,0,2550.0643,I"}];
    
    [ADTestURLSession addResponse:response];
    [[ADAuthorityValidation sharedInstance] addInvalidAuthority:TEST_AUTHORITY];
}

- (void)setupForAcquireTokenWithoutNetworkResponse
{
    // Add a token item to return in the cache
    ADAuthenticationError *error = nil;
    ADTokenCacheItem *item = [self adCreateCacheItem];
    [self.cacheDataSource addOrUpdateItem:item correlationId:nil error:&error];
}

- (void)setupADTelemetryDispatcherWithAggregationRequired:(BOOL)aggregationRequired
{
    ADTelemetryTestDispatcher *dispatcher = [ADTelemetryTestDispatcher new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSDictionary *event)
     {
         [_receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] addDispatcher:dispatcher aggregationRequired:aggregationRequired];
}

- (ADAuthenticationContext *)getTestAuthenticationContext
{
    ADAuthenticationContext *context = [[ADAuthenticationContext alloc] initWithAuthority:TEST_AUTHORITY
                                                                        validateAuthority:NO
                                                                                    error:nil];
    context.tokenCache = self.tokenCache;
    NSAssert(context, @"If this is failing for whatever reason you should probably fix it before trying to run tests.");
    [context setCorrelationId:TEST_CORRELATION_ID];
    
    return context;
}

- (void)testAcquireTokenTelemetry_whenPiiEnabledAndAggregrationOn_shouldReturnOneEventWithPii
{
    [self setupForAcquireTokenWithNetworkResponse];
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    [ADTelemetry sharedInstance].piiEnabled = YES;
    
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
     {
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // verify telemetry output
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    // the following properties are expected in an aggregrated event
    NSDictionary *event = [_receivedEvents firstObject];
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ID)], @"8");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_REQUEST_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CORRELATION_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:@"Microsoft.ADAL.x_client_ver"]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:@"Microsoft.ADAL.x_client_sku"]]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_TYPE)], @"aad");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING)], @"no");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR)], @"AD_PROMPT_AUTO");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESULT_STATUS)], @"succeeded");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESPONSE_TIME)]]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CACHE_EVENT_COUNT)], @"7");
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RT_STATUS)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_MRRT_STATUS)], @"tried");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_FRT_STATUS)], @"tried");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_HTTP_EVENT_COUNT)], @"1");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ERROR_CODE)], @"AD_ERROR_SUCCEEDED");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_OAUTH_ERROR_CODE)], @"");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_SUCCESSFUL)], @"yes");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_HTTP_RESPONSE_CODE)], @"400");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS)], @"no");
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SERVER_ERROR_CODE)]);
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SERVER_SUBERROR_CODE)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RT_AGE)], @"2550.0643");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SPE_INFO)], @"I");
    // expect unhashed Oii
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_NAME)], [MSIDDeviceId applicationName]);//Oii
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_TENANT_ID)], @"6fd1f5cd-a94c-4335-889b-6c598e6d8048");//Oii
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CLIENT_ID)], TEST_CLIENT_ID);//Oii
#if TARGET_OS_IPHONE
    // application_version is only available in unit test framework with host app
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_VERSION)], [MSIDDeviceId applicationVersion]);//Oii
#endif
    // expect hashed Pii
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_DEVICE_ID)], [[MSIDDeviceId deviceTelemetryId] msidComputeSHA256]);//Pii
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_USER_ID)], [TEST_USER_ID msidComputeSHA256]);//Pii
}

- (void)testAcquireTokenTelemetry_whenPiiDisabledAndAggregrationOn_shouldReturnOneEventWithoutPii
{
    [self setupForAcquireTokenWithNetworkResponse];
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    [ADTelemetry sharedInstance].piiEnabled = NO;
    
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
     {
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // verify telemetry output
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    // the following properties are expected in an aggregrated event
    NSDictionary *event = [_receivedEvents firstObject];
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ID)], @"8");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_REQUEST_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CORRELATION_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:@"Microsoft.ADAL.x_client_ver"]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:@"Microsoft.ADAL.x_client_sku"]]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_TYPE)], @"aad");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING)], @"no");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR)], @"AD_PROMPT_AUTO");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESULT_STATUS)], @"succeeded");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESPONSE_TIME)]]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CACHE_EVENT_COUNT)], @"7");
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RT_STATUS)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_MRRT_STATUS)], @"tried");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_FRT_STATUS)], @"tried");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_HTTP_EVENT_COUNT)], @"1");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ERROR_CODE)], @"AD_ERROR_SUCCEEDED");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_OAUTH_ERROR_CODE)], @"");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_SUCCESSFUL)], @"yes");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_HTTP_RESPONSE_CODE)], @"400");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS)], @"no");
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SERVER_ERROR_CODE)]);
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SERVER_SUBERROR_CODE)]);
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RT_AGE)], @"2550.0643");
    XCTAssertEqualObjects([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_SPE_INFO)], @"I");
    // do not expect Oii
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_NAME)]);//Oii
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_TENANT_ID)]);//Oii
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CLIENT_ID)]);//Oii
#if TARGET_OS_IPHONE
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_VERSION)]);//Oii
#endif
    // do not expect Pii
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_DEVICE_ID)]);//Pii
    XCTAssertNil([event objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_USER_ID)]);//Pii
}

- (void)testAcquireTokenTelemetry_whenPiiEnabledAndAggregrationOff_shouldReturnEventsWithPii
{
    [self setupForAcquireTokenWithNetworkResponse];
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    [ADTelemetry sharedInstance].piiEnabled = YES;
    
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
     {
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // verify telemetry output
    // there should be multiple telemetry events as aggregation flag is NO
    XCTAssertTrue([_receivedEvents count] > 1);
    
    // take the API event as a sample and verify the output
    NSDictionary *apiEvent = nil;
    for (NSDictionary *event in _receivedEvents)
    {
        if ([MSID_TELEMETRY_EVENT_API_EVENT isEqualToString:[event objectForKey:(TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME))]])
        {
            apiEvent = event;
        }
    }
    XCTAssertNotNil(apiEvent);
    
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME)], MSID_TELEMETRY_EVENT_API_EVENT);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ID)], @"8");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_REQUEST_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CORRELATION_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:@"Microsoft.ADAL.x_client_ver"]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:@"Microsoft.ADAL.x_client_sku"]]);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_TYPE)], @"aad");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING)], @"no");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR)], @"AD_PROMPT_AUTO");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESULT_STATUS)], @"succeeded");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESPONSE_TIME)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_START_TIME)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_END_TIME)]]);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ERROR_CODE)], @"AD_ERROR_SUCCEEDED");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_SUCCESSFUL)], @"yes");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN)], @"no");
    // expect unhashed Oii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY)], TEST_AUTHORITY);//Oii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_NAME)], [MSIDDeviceId applicationName]);//Oii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_TENANT_ID)], @"6fd1f5cd-a94c-4335-889b-6c598e6d8048");//Oii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CLIENT_ID)], TEST_CLIENT_ID);//Oii
#if TARGET_OS_IPHONE
    // application_version is only available in unit test framework with host app
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_VERSION)], [MSIDDeviceId applicationVersion]);//Oii
#endif
    // expect hashed Pii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_DEVICE_ID)], [[MSIDDeviceId deviceTelemetryId] msidComputeSHA256]);//Pii
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_USER_ID)], [TEST_USER_ID msidComputeSHA256]);//Pii
}

- (void)testAcquireTokenTelemetry_whenPiiDisabledAndAggregrationOff_shouldReturnEventsWithoutPii
{
    [self setupForAcquireTokenWithNetworkResponse];
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    [ADTelemetry sharedInstance].piiEnabled = NO;
    
    ADAuthenticationContext *context = [self getTestAuthenticationContext];
    XCTestExpectation *expectation = [self expectationWithDescription:@"acquireTokenSilentWithResource"];
    
    [context acquireTokenSilentWithResource:TEST_RESOURCE
                                   clientId:TEST_CLIENT_ID
                                redirectUri:TEST_REDIRECT_URL
                                     userId:TEST_USER_ID
                            completionBlock:^(ADAuthenticationResult *result)
     {
         [expectation fulfill];
     }];
    
    [self waitForExpectations:@[expectation] timeout:1];
    
    // verify telemetry output
    // there should be multiple telemetry events as aggregation flag is NO
    XCTAssertTrue([_receivedEvents count] > 1);
    
    // take the API event as a sample and verify the output
    NSDictionary *apiEvent = nil;
    for (NSDictionary *event in _receivedEvents)
    {
        if ([MSID_TELEMETRY_EVENT_API_EVENT isEqualToString:[event objectForKey:(TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME))]])
        {
            apiEvent = event;
        }
    }
    XCTAssertNotNil(apiEvent);
    
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EVENT_NAME)], MSID_TELEMETRY_EVENT_API_EVENT);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ID)], @"8");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_REQUEST_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CORRELATION_ID)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:@"Microsoft.ADAL.x_client_ver"]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:@"Microsoft.ADAL.x_client_sku"]]);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_AUTHORITY_TYPE)], @"aad");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING)], @"no");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR)], @"AD_PROMPT_AUTO");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESULT_STATUS)], @"succeeded");
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_RESPONSE_TIME)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_START_TIME)]]);
    XCTAssertTrue(![NSString msidIsStringNilOrBlank:[apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_END_TIME)]]);
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_API_ERROR_CODE)], @"AD_ERROR_SUCCEEDED");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_SUCCESSFUL)], @"yes");
    XCTAssertEqualObjects([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN)], @"no");
    // do not expect Oii
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_NAME)]);//Oii
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_TENANT_ID)]);//Oii
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_CLIENT_ID)]);//Oii
#if TARGET_OS_IPHONE
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_APPLICATION_VERSION)]);//Oii
#endif
    // do not expect Pii
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_DEVICE_ID)]);//Pii
    XCTAssertNil([apiEvent objectForKey:TELEMETRY_KEY(MSID_TELEMETRY_KEY_USER_ID)]);//Pii
}

@end

