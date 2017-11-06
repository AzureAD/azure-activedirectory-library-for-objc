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
#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADTelemetryDefaultEvent.h"
#import "ADTelemetryAPIEvent.h"
#import "ADTelemetryUIEvent.h"
#import "ADTelemetryHttpEvent.h"
#import "ADTelemetryCacheEvent.h"
#import "ADTelemetryBrokerEvent.h"
#import "ADAuthenticationContext+Internal.h"
#import "ADTestURLSession.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADTelemetryTestDispatcher.h"
#import "ADTelemetryEventStrings.h"

@interface ADTelemetryTests : ADTestCase
{
    NSMutableArray *_receivedEvents;
}

@end

@implementation ADTelemetryTests

- (void)setUp
{
    [super setUp];
    _receivedEvents = [NSMutableArray array];
}

- (void)tearDown
{
    _receivedEvents = nil;
    [super tearDown];
    
    [ADTelemetry sharedInstance].piiEnabled = NO;
}

- (void)setupADTelemetryDispatcherWithAggregationRequired:(BOOL)aggregationRequired
{
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSDictionary* event)
     {
         [_receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] addDispatcher:dispatcher aggregationRequired:aggregationRequired];
}

- (void)testDefaultEventProperties {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    
    // generate telemetry event
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent"
                                                                             requestId:requestId
                                                                         correlationId:[NSUUID UUID]]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry event recorded as we only generated one above
    XCTAssertEqual([_receivedEvents count], 1);
    
    // make sure the default properties are recorded in the telemetry event,
    // i.e. sdk_id, sdk_version, device_id, device_name
    NSDictionary* event = [_receivedEvents firstObject];
    
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.x_client_sku"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.x_client_ver"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.device_id"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.request_id"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.correlation_id"]);
#if TARGET_OS_IPHONE
    // application_version is only available in unit test framework with host app
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.application_version"]);
#endif
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.application_name"]);
}

- (void)testSequentialEvents {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    
    // generate telemetry event 1
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    // generate telemetry event 2
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    ADTelemetryDefaultEvent* event2 = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                          requestId:requestId
                                                                      correlationId:nil];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 2 telemetry events recorded as we generated two
    XCTAssertEqual([_receivedEvents count], 2);
    
    // make sure the 1st event has an event_name, start_time and end_time
    NSDictionary* firstEvent = [_receivedEvents firstObject];
    
    XCTAssertEqual([firstEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent1");
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.response_time"]);

    // make sure the 2nd event has customized_property, event_name, start_time and end_time
    NSDictionary* secondEvent = [_receivedEvents objectAtIndex:1];
    
    XCTAssertEqual([secondEvent objectForKey:@"customized_property"], @"customized_value");
    XCTAssertEqual([secondEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent2");
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.response_time"]);
    
}

- (void)testSequentialEventsWithAggregation {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSUUID* correlationId = [NSUUID UUID];
    
    // generate telemetry event 1
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:correlationId]];
    
    // generate telemetry event 2
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    ADTelemetryDefaultEvent* event2 = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                          requestId:requestId
                                                                      correlationId:correlationId];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry event recorded as aggregation flag is on
    XCTAssertEqual([_receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSDictionary* event = [_receivedEvents firstObject];
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.correlation_id"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.request_id"]);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.response_time"]);
    
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.event_name"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.stop_time"]);
    XCTAssertNil([event objectForKey:@"customized_property"]);
    
}

- (void)testNestedEvents {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    ADTelemetryDefaultEvent* event2 = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                          requestId:requestId
                                                                      correlationId:nil];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 2 telemetry events recorded as we generated two
    XCTAssertEqual([_receivedEvents count], 2);
    
    // the first event recorded is event2
    // make sure it has customized_property, event_name, start_time and end_time
    NSDictionary* firstEvent = [_receivedEvents firstObject];
    XCTAssertEqual([firstEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent2");
    XCTAssertEqual([firstEvent objectForKey:@"customized_property"], @"customized_value");
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    
    // the second event recorded is event1
    // make sure it has event_name, start_time and end_time
    NSDictionary* secondEvent = [_receivedEvents objectAtIndex:1];
    XCTAssertEqual([secondEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent1");
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    
}

- (void)testNestedEventsWithAggregation {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSUUID* correlationId = [NSUUID UUID];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    ADTelemetryDefaultEvent* event2 = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                          requestId:requestId
                                                                      correlationId:correlationId];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:correlationId]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry event recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSDictionary* event = [_receivedEvents firstObject];
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.correlation_id"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.request_id"]);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.response_time"]);
    
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.event_name"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.stop_time"]);
    XCTAssertNil([event objectForKey:@"customized_property"]);
}

- (void)testComplexEvents {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent3"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent3"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent4"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent4"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 4 telemetry events recorded as we generated four
    XCTAssertEqual([_receivedEvents count], 4);
    
    // the first event recorded is event3
    NSDictionary* firstEvent = [_receivedEvents firstObject];
    XCTAssertEqual([firstEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent3");
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([firstEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    
    // the second event recorded is event2
    NSDictionary* secondEvent = [_receivedEvents objectAtIndex:1];
    XCTAssertEqual([secondEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent2");
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([secondEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    
    // the third event recorded is event1
    NSDictionary* thirdEvent = [_receivedEvents objectAtIndex:2];
    XCTAssertEqual([thirdEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent1");
    XCTAssertNotNil([thirdEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([thirdEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
    
    // the fourth event recorded is event4
    NSDictionary* fourthEvent = [_receivedEvents objectAtIndex:3];
    XCTAssertEqual([fourthEvent objectForKey:@"Microsoft.ADAL.event_name"], @"testEvent4");
    XCTAssertNotNil([fourthEvent objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNotNil([fourthEvent objectForKey:@"Microsoft.ADAL.stop_time"]);
}

- (void)testComplexEventsWithAggregation {
    
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSUUID* correlationId = [NSUUID UUID];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent2"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent3"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent3"
                                                                             requestId:requestId
                                                                         correlationId:correlationId]];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent2"
                                                                             requestId:requestId
                                                                         correlationId:nil]];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryAPIEvent alloc] initWithName:@"testEvent1"
                                                                             requestId:requestId
                                                                         correlationId:correlationId]];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent4"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent4"
                                                                             requestId:requestId
                                                                         correlationId:correlationId]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSDictionary* event = [_receivedEvents firstObject];
    
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.correlation_id"]);
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.request_id"]);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertNotNil([event objectForKey:@"Microsoft.ADAL.response_time"]);
    
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.event_name"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.start_time"]);
    XCTAssertNil([event objectForKey:@"Microsoft.ADAL.stop_time"]);
    XCTAssertNil([event objectForKey:@"customized_property"]);
}

- (void)testAdditionalTelemetry_whenSingleEventAndAggregated_shouldReturnAllProperties
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent* event = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                   requestId:requestId correlationId:nil];
    
    [event setClientTelemetry:@"1,111,999,200.056,I"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    NSDictionary* receivedEvent = [_receivedEvents firstObject];
    
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_error_code"], @"111");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_sub_error_code"], @"999");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.rt_age"], @"200.056");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.spe_info"], @"I");
}

- (void)testAdditionalTelemetry_whenMultipleEventsAggregated_shouldReturnLatestProperties
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent* event1 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [event1 setClientTelemetry:@"1,111,999,200.056,I"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event1];
    
    ADTelemetryHttpEvent* event2 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [event2 setClientTelemetry:@"1,888,777,15868,M"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event2];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    NSDictionary* receivedEvent = [_receivedEvents firstObject];
    
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_error_code"], @"888");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_sub_error_code"], @"777");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.rt_age"], @"15868");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.spe_info"], @"M");
}

- (void)testAdditionalTelemetry_whenMultipleEventsAndBlankErrors_shouldReturnAllNilProperties
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent* event1 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [event1 setClientTelemetry:@"1,111,999,200.056,"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event1];
    
    ADTelemetryHttpEvent* event2 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [event2 setClientTelemetry:@"1,,,,"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event2];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    NSDictionary* receivedEvent = [_receivedEvents firstObject];
    
    XCTAssertNil([receivedEvent objectForKey:@"Microsoft.ADAL.server_error_code"]);
    XCTAssertNil([receivedEvent objectForKey:@"Microsoft.ADAL.server_sub_error_code"]);
    XCTAssertNil([receivedEvent objectForKey:@"Microsoft.ADAL.rt_age"]);
    XCTAssertNil([receivedEvent objectForKey:@"Microsoft.ADAL.spe_info"]);
}

- (void)testAdditionalTelemetry_whenTelemetryOnlyInLastEvent_shouldReturnLatestProperties
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    
    ADTelemetryHttpEvent* event1 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event1];
    
    ADTelemetryHttpEvent* event2 = [[ADTelemetryHttpEvent alloc] initWithName:AD_TELEMETRY_EVENT_HTTP_REQUEST
                                                                    requestId:requestId correlationId:nil];
    
    [event2 setClientTelemetry:@"1,5,10,85,I"];
    
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:AD_TELEMETRY_EVENT_HTTP_REQUEST];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                      event:event2];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([_receivedEvents count], 1);
    
    NSDictionary* receivedEvent = [_receivedEvents firstObject];
    
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_error_code"], @"5");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.server_sub_error_code"], @"10");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.rt_age"], @"85");
    XCTAssertEqualObjects([receivedEvent objectForKey:@"Microsoft.ADAL.spe_info"], @"I");
}

- (void)test_telemetryPiiRules_whenPiiEnabledNoAggregationNo_shouldDeletePiiFields
{
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    ADTelemetryDefaultEvent *event = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent"
                                        requestId:requestId
                                    correlationId:[NSUUID UUID]];
    [event setProperty:AD_TELEMETRY_KEY_USER_ID value:@"id1234"];
    [ADTelemetry sharedInstance].piiEnabled = NO;
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId event:event];
    
    NSDictionary *dictionary = [_receivedEvents firstObject];
    XCTAssertNotNil(dictionary);
    XCTAssertNil([dictionary objectForKey:AD_TELEMETRY_KEY_USER_ID]);
}

- (void)test_telemetryPiiRules_whenPiiEnabledYesAggregationNo_shouldHashPiiFields
{
    [self setupADTelemetryDispatcherWithAggregationRequired:NO];
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    ADTelemetryDefaultEvent *event = [[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent"
                                                                         requestId:requestId
                                                                     correlationId:[NSUUID UUID]];
    [event setProperty:AD_TELEMETRY_KEY_USER_ID value:@"id1234"];
    [ADTelemetry sharedInstance].piiEnabled = YES;
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    
    [[ADTelemetry sharedInstance] stopEvent:requestId event:event];
    
    NSDictionary *dictionary = [_receivedEvents firstObject];
    XCTAssertNotNil(dictionary);
    ADAssertStringEquals([dictionary objectForKey:AD_TELEMETRY_KEY_USER_ID], [@"id1234" adComputeSHA256]);
}

- (void)test_telemetryPiiRules_whenPiiEnabledNoAggregationYes_shouldSetPiiFieldsToEmpty
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    ADTelemetryAPIEvent *event = [[ADTelemetryAPIEvent alloc] initWithName:@"testEvent"
                                                                 requestId:requestId
                                                             correlationId:[NSUUID UUID]];
    [event setProperty:AD_TELEMETRY_KEY_USER_ID value:@"id1234"];
    [ADTelemetry sharedInstance].piiEnabled = NO;
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    [[ADTelemetry sharedInstance] stopEvent:requestId event:event];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    NSDictionary *dictionary = [_receivedEvents firstObject];
    XCTAssertNotNil(dictionary);
    XCTAssertNil([dictionary objectForKey:AD_TELEMETRY_KEY_USER_ID]);
}

- (void)test_telemetryPiiRules_whenPiiEnabledYesAggregationYes_shouldHashPiiFields
{
    [self setupADTelemetryDispatcherWithAggregationRequired:YES];
    NSString *requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    ADTelemetryAPIEvent *event = [[ADTelemetryAPIEvent alloc] initWithName:@"testEvent"
                                                                     requestId:requestId
                                                                 correlationId:[NSUUID UUID]];
    [event setProperty:AD_TELEMETRY_KEY_USER_ID value:@"id1234"];
    [ADTelemetry sharedInstance].piiEnabled = YES;
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    [[ADTelemetry sharedInstance] stopEvent:requestId event:event];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    NSDictionary *dictionary = [_receivedEvents firstObject];
    XCTAssertNotNil(dictionary);
    ADAssertStringEquals([dictionary objectForKey:AD_TELEMETRY_KEY_USER_ID], [@"id1234" adComputeSHA256]);
}

@end
