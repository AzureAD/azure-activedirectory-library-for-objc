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
#import "ADTelemetryCacheEvent.h"
#import "ADTelemetryEventStrings.h"

@implementation ADTelemetryCacheEvent

- (void)setTokenType:(NSString*)tokenType
{
    [self setProperty:AD_TELEMETRY_TOKEN_TYPE value:tokenType];
}

- (void)setStatus:(NSString*)status
{
    [self setProperty:@"status" value:status];
}

- (void)setIsRT:(NSString*)isRT
{
    [self setProperty:AD_TELEMETRY_IS_RT value:isRT];
}

- (void)setIsMRRT:(NSString*)isMRRT
{
    [self setProperty:AD_TELEMETRY_IS_MRRT value:isMRRT];
}

- (void)setIsFRT:(NSString*)isFRT
{
    [self setProperty:AD_TELEMETRY_IS_FRT value:isFRT];
}

- (void)setRTStatus:(NSString*)status
{
    [self setProperty:AD_TELEMETRY_RT_STATUS value:status];
}

- (void)setMRRTStatus:(NSString*)status
{
    [self setProperty:AD_TELEMETRY_MRRT_STATUS value:status];
}

- (void)setFRTStatus:(NSString*)status
{
    [self setProperty:AD_TELEMETRY_FRT_STATUS value:status];
}

- (void)addAggregatedPropertiesToDictionary:(NSMutableDictionary*)eventToBeDispatched
{
    [super addAggregatedPropertiesToDictionary:eventToBeDispatched];
    
    (void)eventToBeDispatched;
    NSDictionary* properties = [self getProperties];
    for (NSString* name in properties)
    {
        if ([name isEqualToString:AD_TELEMETRY_RT_STATUS]
            ||[name isEqualToString:AD_TELEMETRY_FRT_STATUS]
            ||[name isEqualToString:AD_TELEMETRY_MRRT_STATUS])
        {
            [eventToBeDispatched setObject:[properties objectForKey:name] forKey:name];
        }
    }
    
    int cacheEventCount = 1;
    if ([eventToBeDispatched objectForKey:AD_TELEMETRY_CACHE_EVENT_COUNT])
    {
        cacheEventCount = [[eventToBeDispatched objectForKey:AD_TELEMETRY_CACHE_EVENT_COUNT] intValue] + 1;
    }
    [eventToBeDispatched setObject:[NSString stringWithFormat:@"%d", cacheEventCount] forKey:AD_TELEMETRY_CACHE_EVENT_COUNT];
}

@end