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
#import "ADTelemetryEventInterface.h"
#import "ADAggregatedDispatcher.h"
#import "ADTelemetryEventStrings.h"
#import "ADTelemetryCollectionRules.h"
#import "ADTelemetryAPIEvent.h"
#import "ADTelemetryUIEvent.h"
#import "ADTelemetryHttpEvent.h"
#import "ADTelemetryCacheEvent.h"
#import "ADTelemetryBrokerEvent.h"
#import "NSMutableDictionary+ADExtensions.h"

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
    for (id<ADTelemetryEventInterface> event in eventsToBeDispatched)
    {
        [self addPropertiesToDictionary:aggregatedEvent event:event];
    }
    
    [_dispatcher dispatchEvent:aggregatedEvent];
}

- (void)receive:(NSString *)requestId
          event:(id<ADTelemetryEventInterface>)event
{
    if ([NSString adIsStringNilOrBlank:requestId] || !event)
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

- (void)addPropertiesToDictionary:(NSMutableDictionary*)aggregatedEvent event:(id<ADTelemetryEventInterface>)event
{
    ADTelemetryDefaultEvent *baseEvent = (ADTelemetryDefaultEvent*)event;
    [aggregatedEvent addEntriesFromDictionary:[baseEvent defaultParameters]];
    
    NSString *eventClassName = NSStringFromClass([event class]);
    
    NSArray* eventProperties = [s_eventPropertiesDictionary objectForKey:eventClassName];
    
    for (NSString* propertyName in eventProperties)
    {
        [self resetCollectedData:aggregatedEvent propertyName:propertyName];
        
        [aggregatedEvent setObjectWithNilCheck:[[event getProperties] objectForKey:propertyName] forKey:propertyName];
        
        [self applyTelemetryCollectionRule:aggregatedEvent propertyName:propertyName];
    }
}

- (void)resetCollectedData:(NSMutableDictionary*)aggregatedEvent propertyName:(NSString *)propertyName
{
    ADTelemetryCollectionBehavior collectionBehavior = [ADTelemetryCollectionRules getTelemetryCollectionRule:propertyName];
    
    if (collectionBehavior == CollectAndUpdate)
    {
        //erase the previous event properties if any
        [aggregatedEvent setObject:@"" forKey:propertyName];
    }
}

- (void)applyTelemetryCollectionRule:(NSMutableDictionary*)aggregatedEvent propertyName:(NSString *)propertyName
{
    ADTelemetryCollectionBehavior collectionBehavior = [ADTelemetryCollectionRules getTelemetryCollectionRule:propertyName];
    
    switch (collectionBehavior) {
        case CollectAndCount:
            [self applyTelemetryCollectionRuleCount:aggregatedEvent propertyName:propertyName];
            break;
            
        case CollectAndUpdate:
        case CollectOnly:
        default:
            break;
    }
}

- (void)applyTelemetryCollectionRuleCount:(NSMutableDictionary*)aggregatedEvent propertyName:(NSString *)propertyName
{
    int eventCount = [[aggregatedEvent objectForKey:propertyName] intValue];
    
    [aggregatedEvent setObject:[NSString stringWithFormat:@"%d", ++eventCount] forKey:propertyName];
}

+ (void)initialize
{
    if (self == [ADAggregatedDispatcher class])
    {
        s_eventPropertiesDictionary = @{
                                      NSStringFromClass([ADTelemetryAPIEvent class]): @[
                                              // default properties apply to all events
                                              AD_TELEMETRY_PROPERTY_NAME_REQUEST_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_CORRELATION_ID,
                                              
                                              AD_TELEMETRY_PROPERTY_NAME_AUTHORITY_TYPE,
                                              AD_TELEMETRY_PROPERTY_NAME_AUTHORITY_VALIDATION_STATUS,
                                              AD_TELEMETRY_PROPERTY_NAME_EXTENDED_EXPIRES_ON_SETTING,
                                              AD_TELEMETRY_PROPERTY_NAME_PROMPT_BEHAVIOR,
                                              AD_TELEMETRY_PROPERTY_NAME_RESULT_STATUS,
                                              AD_TELEMETRY_PROPERTY_NAME_IDP,
                                              AD_TELEMETRY_PROPERTY_NAME_TENANT_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_USER_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_RESPONSE_TIME,
                                              AD_TELEMETRY_PROPERTY_NAME_CLIENT_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_API_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_USER_CANCEL,
                                              AD_TELEMETRY_PROPERTY_NAME_ERROR_CODE,
                                              AD_TELEMETRY_PROPERTY_NAME_ERROR_DOMAIN,
                                              AD_TELEMETRY_PROPERTY_NAME_PROTOCOL_CODE,
                                              AD_TELEMETRY_PROPERTY_NAME_IS_SUCCESSFUL
                                              ],
                                      NSStringFromClass([ADTelemetryUIEvent class]): @[
                                              // default properties apply to all events
                                              AD_TELEMETRY_PROPERTY_NAME_REQUEST_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_CORRELATION_ID,
                                              
                                              AD_TELEMETRY_PROPERTY_NAME_LOGIN_HINT,
                                              AD_TELEMETRY_PROPERTY_NAME_NTLM_HANDLED
                                              ],
                                      NSStringFromClass([ADTelemetryHttpEvent class]): @[
                                              // default properties apply to all events
                                              AD_TELEMETRY_PROPERTY_NAME_REQUEST_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_CORRELATION_ID,
                                              
                                              AD_TELEMETRY_PROPERTY_NAME_OAUTH_ERROR_CODE
                                              ],
                                      NSStringFromClass([ADTelemetryCacheEvent class]): @[
                                              // default properties apply to all events
                                              AD_TELEMETRY_PROPERTY_NAME_REQUEST_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_CORRELATION_ID,
                                              
                                              AD_TELEMETRY_PROPERTY_NAME_RT_STATUS,
                                              AD_TELEMETRY_PROPERTY_NAME_FRT_STATUS,
                                              AD_TELEMETRY_PROPERTY_NAME_MRRT_STATUS
                                              ],
                                      NSStringFromClass([ADTelemetryBrokerEvent class]): @[
                                              // default properties apply to all events
                                              AD_TELEMETRY_PROPERTY_NAME_REQUEST_ID,
                                              AD_TELEMETRY_PROPERTY_NAME_CORRELATION_ID,
                                              
                                              AD_TELEMETRY_PROPERTY_NAME_BROKER_APP,
                                              AD_TELEMETRY_PROPERTY_NAME_BROKER_VERSION
                                              ],
                                      };
    }
}

@end
