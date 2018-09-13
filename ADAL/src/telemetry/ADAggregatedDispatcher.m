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
#import "MSIDTelemetryEventInterface.h"
#import "ADAggregatedDispatcher.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADTelemetryCollectionRules.h"
#import "ADTelemetryAPIEvent.h"
#import "MSIDTelemetryUIEvent.h"
#import "MSIDTelemetryHttpEvent.h"
#import "MSIDTelemetryCacheEvent.h"
#import "ADTelemetryBrokerEvent.h"
#import "NSMutableDictionary+MSIDExtensions.h"

@implementation ADAggregatedDispatcher

static NSDictionary *s_eventPropertiesDictionary;

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDispatcher:(id<ADDispatcher>)dispatcher
{
    self = [super initWithDispatcher:dispatcher];
    return self;
}

- (void)flush:(NSString*)requestId
{
    [_dispatchLock lock]; //avoid access conflict when manipulating _objectsToBeDispatched
    NSArray* eventsToBeDispatched = [_objectsToBeDispatched objectForKey:requestId];
    [_objectsToBeDispatched removeObjectForKey:requestId];
    [_dispatchLock unlock];
    
    NSMutableDictionary* aggregatedEvent = [NSMutableDictionary new];
    for (id<MSIDTelemetryEventInterface> event in eventsToBeDispatched)
    {
        [self addPropertiesToDictionary:aggregatedEvent event:event];
    }
    
    [self dispatchEvent:aggregatedEvent];
}

- (void)receive:(NSString *)requestId
          event:(id<MSIDTelemetryEventInterface>)event
{
    if ([NSString msidIsStringNilOrBlank:requestId] || !event)
    {
        return;
        
    }
    
    [_dispatchLock lock]; //make sure no one changes _objectsToBeDispatched while using it
    NSMutableArray* eventsForRequestId = [_objectsToBeDispatched objectForKey:requestId];
    if (!eventsForRequestId)
    {
        eventsForRequestId = [NSMutableArray new];
        [_objectsToBeDispatched setObject:eventsForRequestId forKey:requestId];
    }
    
    [eventsForRequestId addObject:event];
    [_dispatchLock unlock];
    
}

- (void)addPropertiesToDictionary:(NSMutableDictionary*)aggregatedEvent event:(id<MSIDTelemetryEventInterface>)event
{
    [aggregatedEvent addEntriesFromDictionary:[MSIDTelemetryBaseEvent defaultParameters]];
    
    NSString *eventClassName = NSStringFromClass([event class]);
    
    NSArray* eventProperties = [s_eventPropertiesDictionary objectForKey:eventClassName];
    
    for (NSString* propertyName in eventProperties)
    {
        ADTelemetryCollectionBehavior collectionBehavior = [ADTelemetryCollectionRules getTelemetryCollectionRule:propertyName];
        
        NSString* propertyKey = propertyName;
        
        if (collectionBehavior == CollectAndUpdate)
        {
            //erase the previous event properties only if there were any previously
            if ([aggregatedEvent objectForKey:propertyKey])
            {
                [aggregatedEvent removeObjectForKey:propertyKey];
            }
        }
        
        if (collectionBehavior != CollectAndCount)
        {
            [aggregatedEvent msidSetObjectIfNotNil:[event propertyWithName:propertyName] forKey:propertyKey];
        }
        else
        {
            int eventCount = [[aggregatedEvent objectForKey:propertyKey] intValue];
            [aggregatedEvent setObject:[NSString stringWithFormat:@"%d", ++eventCount] forKey:propertyKey];
        }
    }
}

+ (void)initialize
{
    if (self == [ADAggregatedDispatcher class])
    {
        s_eventPropertiesDictionary = @{
                                      NSStringFromClass([ADTelemetryAPIEvent class]): @[
                                              // default properties apply to all events
                                              MSID_TELEMETRY_KEY_REQUEST_ID,
                                              MSID_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              MSID_TELEMETRY_KEY_AUTHORITY_TYPE,
                                              MSID_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS,
                                              MSID_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING,
                                              MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR,
                                              MSID_TELEMETRY_KEY_RESULT_STATUS,
                                              MSID_TELEMETRY_KEY_IDP,
                                              MSID_TELEMETRY_KEY_TENANT_ID,
                                              MSID_TELEMETRY_KEY_USER_ID,
                                              MSID_TELEMETRY_KEY_RESPONSE_TIME,
                                              MSID_TELEMETRY_KEY_CLIENT_ID,
                                              MSID_TELEMETRY_KEY_API_ID,
                                              MSID_TELEMETRY_KEY_USER_CANCEL,
                                              MSID_TELEMETRY_KEY_API_ERROR_CODE,
                                              MSID_TELEMETRY_KEY_ERROR_DOMAIN,
                                              MSID_TELEMETRY_KEY_PROTOCOL_CODE,
                                              MSID_TELEMETRY_KEY_IS_SUCCESSFUL
                                              ],
                                      NSStringFromClass([MSIDTelemetryUIEvent class]): @[
                                              // default properties apply to all events
                                              MSID_TELEMETRY_KEY_REQUEST_ID,
                                              MSID_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              MSID_TELEMETRY_KEY_LOGIN_HINT,
                                              MSID_TELEMETRY_KEY_NTLM_HANDLED,
                                              MSID_TELEMETRY_KEY_UI_EVENT_COUNT
                                              ],
                                      NSStringFromClass([MSIDTelemetryHttpEvent class]): @[
                                              // default properties apply to all events
                                              MSID_TELEMETRY_KEY_REQUEST_ID,
                                              MSID_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              MSID_TELEMETRY_KEY_OAUTH_ERROR_CODE,
                                              MSID_TELEMETRY_KEY_HTTP_RESPONSE_CODE,
                                              MSID_TELEMETRY_KEY_HTTP_EVENT_COUNT,
                                              MSID_TELEMETRY_KEY_SERVER_ERROR_CODE,
                                              MSID_TELEMETRY_KEY_SERVER_SUBERROR_CODE,
                                              MSID_TELEMETRY_KEY_RT_AGE,
                                              MSID_TELEMETRY_KEY_SPE_INFO
                                              ],
                                      NSStringFromClass([MSIDTelemetryCacheEvent class]): @[
                                              // default properties apply to all events
                                              MSID_TELEMETRY_KEY_REQUEST_ID,
                                              MSID_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              MSID_TELEMETRY_KEY_RT_STATUS,
                                              MSID_TELEMETRY_KEY_FRT_STATUS,
                                              MSID_TELEMETRY_KEY_MRRT_STATUS,
                                              MSID_TELEMETRY_KEY_CACHE_EVENT_COUNT,
                                              MSID_TELEMETRY_KEY_SPE_INFO,
                                              MSID_TELEMETRY_KEY_WIPE_APP,
                                              MSID_TELEMETRY_KEY_WIPE_TIME
                                              ],
                                      NSStringFromClass([ADTelemetryBrokerEvent class]): @[
                                              // default properties apply to all events
                                              MSID_TELEMETRY_KEY_REQUEST_ID,
                                              MSID_TELEMETRY_KEY_CORRELATION_ID,
                                              
                                              MSID_TELEMETRY_KEY_BROKER_APP,
                                              MSID_TELEMETRY_KEY_BROKER_VERSION
                                              ],
                                      };
    }
}

@end
