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
#import "ADDefaultEvent.h"

typedef void(^TestCallback)(NSArray* event);

@interface TestDispatcher : NSObject <ADDispatcher>
{
    TestCallback _testCallback;
}

- (void)setTestCallback:(TestCallback)callback;
@end

@implementation TestDispatcher

- (void)setTestCallback:(TestCallback)callback
{
    _testCallback = callback;
}

- (void)dispatch:(NSArray*)event
{
    // call _testCallback when it receives telemetry event
    // this is for the purpose of unit test
    if (_testCallback)
    {
        _testCallback(event);
    }
}

@end

@interface ADTelemetryTests : XCTestCase

@end

@implementation ADTelemetryTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testDefaultEventProperties {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
    {
        [receivedEvents addObject:event];
    }];
    
    // register the dispatcher
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
    // generate telemetry event
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent"]];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 1 telemetry event recorded as we only generated one above
    XCTAssertEqual([receivedEvents count], 1);
    
    // make sure the default properties are recorded in the telemetry event,
    // i.e. sdk_id, sdk_version, device_id, device_name
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"sdk_id"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"sdk_id"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"sdk_version"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"sdk_version"], 1);
#if TARGET_OS_IPHONE
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"device_id"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"device_id"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"device_name"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"device_name"], 1);
#endif
    // application_name, application_version are also default properties,
    // but they are not available in unit test framework, so we omit them here
    
}

- (void)testSequentialEvents {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
    // generate telemetry event 1
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    // generate telemetry event 2
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    ADDefaultEvent* event2 = [[ADDefaultEvent alloc] initWithName:@"testEvent2"];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 2 telemetry events recorded as we generated two
    XCTAssertEqual([receivedEvents count], 2);
    
    // make sure the 1st event has an event_name, start_time and stop_time
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"event_name"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 1);

    // make sure the 2nd event has customized_property, event_name, start_time and stop_time
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"customized_property"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"customized_property"], 1);
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"event_name"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 1);
    
}

- (void)testSequentialEventsWithAggregation {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher with aggregation
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
    // generate telemetry event 1
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    // generate telemetry event 2
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    ADDefaultEvent* event2 = [[ADDefaultEvent alloc] initWithName:@"testEvent2"];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 1 telemetry event recorded as aggregation flag is on
    XCTAssertEqual([receivedEvents count], 1);
    
    // make sure the aggregated event has 2 event_name, start_time and stop_time
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 2);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 2);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 2);
    
    // the aggregated event should have 1 customized_property
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"customized_property"], 1);
    
}

- (void)testNestedEvents {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    ADDefaultEvent* event2 = [[ADDefaultEvent alloc] initWithName:@"testEvent2"];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 2 telemetry events recorded as we generated two
    XCTAssertEqual([receivedEvents count], 2);
    
    // the first event recorded is event2
    // make sure it has customized_property, event_name, start_time and stop_time
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"event_name"] isEqualToString:@"testEvent2"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"customized_property"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"customized_property"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 1);
    
    // the second event recorded is event1
    // make sure it has event_name, start_time and stop_time
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"event_name"] isEqualToString:@"testEvent1"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"stop_time"], 1);
    
}

- (void)testNestedEventsWithAggregation {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher with aggregation
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    ADDefaultEvent* event2 = [[ADDefaultEvent alloc] initWithName:@"testEvent2"];
    [event2 setProperty:@"customized_property" value:@"customized_value"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:event2];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 1 telemetry event recorded as aggregation flag is ON
    XCTAssertEqual([receivedEvents count], 1);
    
    // make sure there is one customized_property, two event_name, start_time and stop_time
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"customized_property"], 1);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 2);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 2);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 2);
}

- (void)testComplexEvents {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:NO];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent3"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent3"]];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent2"]];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent4"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent4"]];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 4 telemetry events recorded as we generated four
    XCTAssertEqual([receivedEvents count], 4);
    
    // the first event recorded is event3
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents firstObject]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent3"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents firstObject]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 1);
    
    // the second event recorded is event2
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent2"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:1]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:1]
                             propertyName:@"stop_time"], 1);
    
    // the third event recorded is event1
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents objectAtIndex:2]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent1"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:2]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:2]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:2]
                             propertyName:@"stop_time"], 1);
    
    // the fourth event recorded is event4
    XCTAssertTrue([[self getPropertyFromEvent:[receivedEvents objectAtIndex:3]
                                 propertyName:@"event_name"] isEqualToString:@"testEvent4"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"event_name"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:3]
                                  propertyName:@"start_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"start_time"], 1);
    
    XCTAssertNotNil([self getPropertyFromEvent:[receivedEvents objectAtIndex:3]
                                  propertyName:@"stop_time"]);
    XCTAssertEqual([self getPropertyCount:[receivedEvents objectAtIndex:3]
                             propertyName:@"stop_time"], 1);
}

- (void)testComplexEventsWithAggregation {
    // new a dispatcher
    TestDispatcher* dispatcher = [TestDispatcher new];
    NSMutableArray* receivedEvents = [NSMutableArray new];
    
    // the dispatcher will store the telemetry events it receives
    [dispatcher setTestCallback:^(NSArray* event)
     {
         [receivedEvents addObject:event];
     }];
    
    // register the dispatcher
    [[ADTelemetry getInstance] registerDispatcher:dispatcher aggregationRequired:YES];
    
    // generate telemetry event1 nested with event2
    NSString* requestId = [[ADTelemetry getInstance] registerNewRequest];
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent1"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent2"];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent3"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent3"]];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent2"]];
    
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent1"]];
    
    [[ADTelemetry getInstance] startEvent:requestId eventName:@"testEvent4"];
    [[ADTelemetry getInstance] stopEvent:requestId
                                   event:[[ADDefaultEvent alloc] initWithName:@"testEvent4"]];
    
    [[ADTelemetry getInstance] flush];
    
    // there should be 1 telemetry events recorded as aggregation flag is ON
    XCTAssertEqual([receivedEvents count], 1);
    
    // // make sure there are four event_name, start_time and stop_time
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"event_name"], 4);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"start_time"], 4);
    
    XCTAssertEqual([self getPropertyCount:[receivedEvents firstObject]
                             propertyName:@"stop_time"], 4);
}

- (NSString*)getPropertyFromEvent:(NSArray*)event
                 propertyName:(NSString*)propertyName
{
    for (NSArray* propertyValuePair in event)
    {
        if ([[propertyValuePair objectAtIndex:0] isEqualToString:propertyName])
        {
            return [propertyValuePair objectAtIndex:1];
        }
    }
    return nil;
}

- (NSInteger)getPropertyCount:(NSArray*)event
                 propertyName:(NSString*)propertyName
{
    NSInteger count = 0;
    for (NSArray* propertyValuePair in event)
    {
        if ([[propertyValuePair objectAtIndex:0] isEqualToString:propertyName])
        {
            count++;
        }
    }
    return count;
}

@end
