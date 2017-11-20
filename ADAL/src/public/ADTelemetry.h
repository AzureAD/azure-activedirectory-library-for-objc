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

/*!
    @protocol ADDispatcher
 
    Developer should implement it in order to receive telemetry events.
 
    Usage: an instance of ADDispatcher implementation is required when registerring dispatcher for ADTelemetry.
 */
@protocol ADDispatcher <NSObject>

/*!
    Callback function that will be called by ADAL when telemetry events are flushed.
    @param  event        An event is represented by a dictionary of key-value properties.
 */
- (void)dispatchEvent:(nonnull NSDictionary<NSString*, NSString*> *)event;

@end

/*!
    @class ADTelemetry
 
    The central class for ADAL telemetry.
 
    Usage: Get a singleton instance of ADTelemetry; register a dispatcher for receiving telemetry events.
 */
@interface ADTelemetry : NSObject

/*!
    Get a singleton instance of ADTelemetry.
 */
+ (nonnull ADTelemetry*)sharedInstance;

/*!
Setting piiEnabled to YES, will allow ADAL to return fields with user information in the telemetry events. ADAL does not send telemetry data by itself to any server. If apps want to collect ADAL telemetry with user information they must setup the telemetry callback and set this flag on. By default ADAL will not return any user information in telemetry.
 */
@property (nonatomic) BOOL piiEnabled;

/*!
    Register a telemetry dispatcher for receiving telemetry events.
    @param dispatcher            An instance of ADDispatcher implementation.
    @param aggregationRequired   If set NO, all telemetry events collected by ADAL will be dispatched;
                                 If set YES, ADAL will dispatch only one event for each acquire token call, 
                                    where the event is a brief summary (but with far less details) of all telemetry events for that acquire token call.
 */
- (void)addDispatcher:(nonnull id<ADDispatcher>)dispatcher
  aggregationRequired:(BOOL)aggregationRequired;

/*!
 Remove a telemetry dispatcher added for receiving telemetry events.
 @param dispatcher            An instance of ADDispatcher implementation added to the dispatches before.
 */
- (void)removeDispatcher:(nonnull id<ADDispatcher>)dispatcher;

/*!
 Remove all telemetry dispatchers added to the dispatchers collection.
 */
- (void)removeAllDispatchers;

@end
