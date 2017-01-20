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
#import "ADAuthenticationContext+Internal.h"
#import "ADTestURLSession.h"
#import "XCTestCase+TestHelperMethods.h"
#import "ADTokenCache+Internal.h"
#import "ADTokenCacheItem.h"
#import "ADTelemetryTestDispatcher.h"

@interface ADTelemetryTests : XCTestCase

@end

@implementation ADTelemetryTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testDefaultEventProperties {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
    {
        [receivedEvents addObject:event];
    }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
    // generate telemetry event
    NSString* requestId = [[ADTelemetry sharedInstance] registerNewRequest];
    [[ADTelemetry sharedInstance] startEvent:requestId eventName:@"testEvent"];
    [[ADTelemetry sharedInstance] stopEvent:requestId
                                   event:[[ADTelemetryDefaultEvent alloc] initWithName:@"testEvent"
                                                                             requestId:requestId
                                                                         correlationId:[NSUUID UUID]]];
    
    [[ADTelemetry sharedInstance] flush:requestId];
    
    // there should be 1 telemetry event recorded as we only generated one above
    XCTAssertEqual([receivedEvents count], 1);
    
    // make sure the default properties are recorded in the telemetry event,
    // i.e. sdk_id, sdk_version, device_id, device_name
    NSArray* event = [receivedEvents firstObject];
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"x-client-SKU"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"x-client-Ver"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"device_id"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"request_id"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"correlation_id"], 1);
#if TARGET_OS_IPHONE
    // application_version is only available in unit test framework with host app
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"application_version"], 1);
#endif
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"application_name"], 1);
}

- (void)testSequentialEvents {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
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
    XCTAssertEqual([receivedEvents count], 2);
    
    // make sure the 1st event has an event_name, start_time and stop_time
    NSArray* firstEvent = [receivedEvents firstObject];
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"stop_time"], 1);

    // make sure the 2nd event has customized_property, event_name, start_time and stop_time
    NSArray* secondEvent = [receivedEvents objectAtIndex:1];
    
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"customized_property"], 1);

    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"stop_time"], 1);
    
}

- (void)testSequentialEventsWithAggregation {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    NSUUID* correlationId = [NSUUID UUID];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher with aggregation
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
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
    XCTAssertEqual([receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSArray* event = [receivedEvents firstObject];
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"correlation_id"], 1);
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"request_id"], 1);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"response_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"event_name"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"start_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"stop_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"customized_property"], 0);
    
}

- (void)testNestedEvents {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
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
    XCTAssertEqual([receivedEvents count], 2);
    
    // the first event recorded is event2
    // make sure it has customized_property, event_name, start_time and stop_time
    NSArray* firstEvent = [receivedEvents firstObject];
    XCTAssertTrue([[self adGetPropertyFromEvent:firstEvent
                                  propertyName:@"event_name"] isEqualToString:@"testEvent2"]);
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"customized_property"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:firstEvent
                             propertyName:@"stop_time"], 1);
    
    // the second event recorded is event1
    // make sure it has event_name, start_time and stop_time
    NSArray* secondEvent = [receivedEvents objectAtIndex:1];
    XCTAssertTrue([[self adGetPropertyFromEvent:secondEvent
                                  propertyName:@"event_name"] isEqualToString:@"testEvent1"]);
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:secondEvent
                             propertyName:@"stop_time"], 1);
    
}

- (void)testNestedEventsWithAggregation {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    NSUUID* correlationId = [NSUUID UUID];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher with aggregation
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
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
    XCTAssertEqual([receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSArray* event = [receivedEvents firstObject];
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"correlation_id"], 1);
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"request_id"], 1);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"response_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"event_name"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"start_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"stop_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"customized_property"], 0);
}

- (void)testComplexEvents {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
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
    XCTAssertEqual([receivedEvents count], 4);
    
    // the first event recorded is event3
    XCTAssertTrue([[self adGetPropertyFromEvent:[receivedEvents firstObject]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent3"]);
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 1);
    
    // the second event recorded is event2
    XCTAssertTrue([[self adGetPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent2"]);
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"stop_time"], 1);
    
    // the third event recorded is event1
    XCTAssertTrue([[self adGetPropertyFromEvent:[receivedEvents objectAtIndex:2]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent1"]);
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"stop_time"], 1);
    
    // the fourth event recorded is event4
    XCTAssertTrue([[self adGetPropertyFromEvent:[receivedEvents objectAtIndex:3]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent4"]);
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"event_name"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"start_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"stop_time"], 1);
}

- (void)testComplexEventsWithAggregation {
    // new a dispatcher
    ADTelemetryTestDispatcher* dispatcher = [ADTelemetryTestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    NSUUID* correlationId = [NSUUID UUID];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry sharedInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
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
    XCTAssertEqual([receivedEvents count], 1);
    
    // the aggregated event outputs the default properties like correlation_id, request_id, etc.
    NSArray* event = [receivedEvents firstObject];
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"correlation_id"], 1);
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"request_id"], 1);
    
    // it will also outputs some designated properties like response_time, but not for event_name, etc.
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"response_time"], 1);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"event_name"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"start_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"stop_time"], 0);
    
    XCTAssertEqual([self adGetPropertyCount:event
                             propertyName:@"customized_property"], 0);
}

@end
