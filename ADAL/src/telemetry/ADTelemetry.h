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

@class ADDefaultDispatcher;

/*!
    @protocol ADDispatcher
 
    Developer should implement it in order to receive telemetry events.
 
    Usage: an instance of ADDispatcher implementation is required when registerring dispatcher for ADTelemetry.
 */
@protocol ADDispatcher <NSObject>

/*!
    Callback function that will be called by ADAL when telemetry events are flushed.
    @param  event        An array of property-value pairs. Each pair is also stored in an array whose size is 2. 
                         So event is a two-dimentional array.
 */
- (void)dispatch:(NSArray*)event;

@end

/*!
    @class ADTelemetry
 
    The central class for ADAL telemetry.
 
    Usage: Get a singleton instance of ADTelemetry; register a dispatcher for receiving telemetry events.
    Telemetry events will be flushed when function flush is called by developer.
 */
@interface ADTelemetry : NSObject
{
    ADDefaultDispatcher* _dispatcher;
    NSMutableDictionary* _eventTracking;
}

/*!
    Get a singleton instance of ADTelemetry.
 */
+ (ADTelemetry*)getInstance;

/*!
    Register a telemetry dispatcher for receiving telemetry events.
    @param dispatcher            An instance of ADDispatcher implementation.
    @param aggregationRequired   Specifies if telemetry events will be aggregated on client, 
                                 i.e. all events of a single request will be aggregated as one single event.
 */
- (void)registerDispatcher:(id<ADDispatcher>)dispatcher
       aggregationRequired:(BOOL)aggregationRequired;

/*!
    Flush all cached telemetry events to the registered dispatcher.
 */
- (void)flush;

@end