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

#import "ADTelemetryCacheEvent.h"
#import "ADTelemetryEventStrings.h"

@implementation ADTelemetryCacheEvent

- (void)setTokenType:(NSString*)tokenType
{
    [self setProperty:TELEMETRY_TOKEN_TYPE value:tokenType];
}

- (void)setStatus:(NSString*)status
{
    [self setProperty:@"status" value:status];
}

- (void)setIsRT:(NSString*)isRT
{
    [self setProperty:TELEMETRY_IS_RT value:isRT];
}

- (void)setIsMRRT:(NSString*)isMRRT
{
    [self setProperty:TELEMETRY_IS_MRRT value:isMRRT];
}

- (void)setIsFRT:(NSString*)isFRT
{
    [self setProperty:TELEMETRY_IS_FRT value:isFRT];
}

- (void)processEvent:(NSMutableDictionary*)eventToBeDispatched
{
    [super processEvent:eventToBeDispatched];
    
    (void)eventToBeDispatched;
    NSArray* properties = [self getProperties];
    for (NSArray* property in properties)
    {
        if ([property[0] isEqualToString:TELEMETRY_IS_RT]
            ||[property[0] isEqualToString:TELEMETRY_IS_MRRT]
            ||[property[0] isEqualToString:TELEMETRY_IS_FRT])
        {
            [eventToBeDispatched removeObjectForKey:TELEMETRY_IS_RT];
            [eventToBeDispatched removeObjectForKey:TELEMETRY_IS_MRRT];
            [eventToBeDispatched removeObjectForKey:TELEMETRY_IS_FRT];
            [eventToBeDispatched setObject:property[1] forKey:property[0]];
        }
    }
    
    int cacheEventCount = 1;
    if ([eventToBeDispatched objectForKey:TELEMETRY_CACHE_EVENT_COUNT])
    {
        cacheEventCount = [[eventToBeDispatched objectForKey:TELEMETRY_CACHE_EVENT_COUNT] intValue] + 1;
    }
    [eventToBeDispatched setObject:[NSString stringWithFormat:@"%d", cacheEventCount] forKey:TELEMETRY_CACHE_EVENT_COUNT];
}

@end