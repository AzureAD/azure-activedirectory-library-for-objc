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

#import "ADTelemetry.h"
#import "ADTelemetry+Internal.h"
#import "ADEventInterface.h"
#import "ADDefaultDispatcher.h"
#import "ADAggregatedDispatcher.h"

static NSString* const s_delimiter = @"|";

@implementation ADTelemetry

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id) initInternal
{
    self = [super init];
    if (self)
    {
        _eventTracking = [NSMutableDictionary new];
    }
    return self;
}

+ (ADTelemetry*)getInstance
{
    static dispatch_once_t once;
    static ADTelemetry* singleton = nil;
    
    dispatch_once(&once, ^{
        singleton = [[ADTelemetry alloc] initInternal];
    });
    
    return singleton;
}

- (void)registerDispatcher:(id<ADDispatcher>)dispatcher
       aggregationRequired:(BOOL)aggregationRequired
{
    @synchronized(self)
    {
        SAFE_ARC_RELEASE(_dispatcher);
        if (aggregationRequired)
        {
            _dispatcher = [[ADAggregatedDispatcher alloc] initWithDispatcher:dispatcher];
        }
        else
        {
            _dispatcher = [[ADDefaultDispatcher alloc] initWithDispatcher:dispatcher];
        }
        SAFE_ARC_RETAIN(_dispatcher);
    }
}

- (void)flush
{
    @synchronized(self)
    {
        if (_dispatcher)
        {
            [_dispatcher flush];
        }
    }
}

- (void)dealloc
{
    SAFE_ARC_RELEASE(_dispatcher);
    _dispatcher = nil;
    SAFE_ARC_RELEASE(_eventTracking);
    _eventTracking = nil;
    
    SAFE_ARC_SUPER_DEALLOC();
}

@end

@implementation ADTelemetry (Internal)

- (NSString*)registerNewRequest
{
    return [[NSUUID UUID] UUIDString];
}

- (void)startEvent:(NSString*)requestId
         eventName:(NSString*)eventName
{
    if ([NSString adIsStringNilOrBlank:requestId] || [NSString adIsStringNilOrBlank:eventName])
    {
        return;
    }
    
    NSDate* currentTime = [NSDate date];
    [_eventTracking setObject:currentTime
                       forKey: [self getEventTrackingKey:requestId eventName:eventName]];
}

- (void)stopEvent:(NSString*)requestId
            event:(id<ADEventInterface>)event
{
    NSString* eventName = [self getPropertyFromEvent:event propertyName:@"event_name"];
    
    if ([NSString adIsStringNilOrBlank:requestId] || [NSString adIsStringNilOrBlank:eventName] || !event)
    {
        return;
    }
    
    NSString* key = [self getEventTrackingKey:requestId eventName:eventName];
    NSDate* startTime = [_eventTracking objectForKey:key];
    if (!startTime)
    {
        return;
    }
    [event setStartTime:startTime];
    [_eventTracking removeObjectForKey:key];
    
    NSDate* stopTime = [NSDate date];
    [event setStopTime:stopTime];
    
    [self dispatchEventNow:requestId event:event];
}

- (void)dispatchEventNow:(NSString*)requestId
                   event:(id<ADEventInterface>)event
{
    @synchronized(self)//Guard against thread-unsafe callback and modification of _dispatcher after the check
    {
        if (_dispatcher)
        {
            [_dispatcher receive:requestId event:event];
        }
    }
}

- (NSString*)getEventTrackingKey:(NSString*)requestId
                       eventName:(NSString*)eventName
{
    return [NSString stringWithFormat:@"%@%@%@", requestId, s_delimiter, eventName];
}

- (NSString*)getPropertyFromEvent:(id<ADEventInterface>)event
                     propertyName:(NSString*)propertyName
{
    NSArray* properties = [event getProperties];
    for (NSArray* propertyValuePair in properties)
    {
        if ([[propertyValuePair objectAtIndex:0] isEqualToString:propertyName])
        {
            return [propertyValuePair objectAtIndex:1];
        }
    }
    return nil;
}

@end