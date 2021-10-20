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

#import "ADALTelemetry.h"
#import "MSIDTelemetry.h"
#import "MSIDTelemetry+Internal.h"
#import "ADALDefaultDispatcher.h"
#import "ADALAggregatedDispatcher.h"

@implementation ADALTelemetry

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

-(id)initInternal
{
    return [super init];
}

+ (ADALTelemetry*)sharedInstance
{
    static dispatch_once_t once;
    static ADALTelemetry* singleton = nil;
    
    dispatch_once(&once, ^{
        singleton = [[ADALTelemetry alloc] initInternal];
    });
    
    return singleton;
}

- (void)addDispatcher:(nonnull id<ADDispatcher>)dispatcher
       aggregationRequired:(BOOL)aggregationRequired
{
    ADALDefaultDispatcher *telemetryDispatcher = nil;
    
    if (aggregationRequired)
    {
        telemetryDispatcher = [[ADALAggregatedDispatcher alloc] initWithDispatcher:dispatcher];
    }
    else
    {
        telemetryDispatcher = [[ADALDefaultDispatcher alloc] initWithDispatcher:dispatcher];
    }
    
    [[MSIDTelemetry sharedInstance] addDispatcher:telemetryDispatcher];
}

- (void)removeDispatcher:(nonnull id<ADDispatcher>)dispatcher
{
    [[MSIDTelemetry sharedInstance] findAndRemoveDispatcher:dispatcher];
}

- (void)removeAllDispatchers
{
    [[MSIDTelemetry sharedInstance] removeAllDispatchers];
}

- (BOOL)piiEnabled
{
    return [[MSIDTelemetry sharedInstance] piiEnabled];
}

- (void)setPiiEnabled:(BOOL)piiEnabled
{
    [[MSIDTelemetry sharedInstance] setPiiEnabled:piiEnabled];
}

@end
