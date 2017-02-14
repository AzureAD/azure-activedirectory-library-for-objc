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
#import "ADDefaultDispatcher.h"

@implementation ADDefaultDispatcher

- (id)init
{
    //Ensure that the appropriate init function is called. This will cause the runtime to throw.
    [super doesNotRecognizeSelector:_cmd];
    return nil;
}

- (id)initWithDispatcher:(id<ADDispatcher>)dispatcher
{
    self = [super init];
    if (self)
    {
        _objectsToBeDispatched = [NSMutableDictionary new];
        _dispatchLock = [NSLock new];
        
        _dispatcher = dispatcher;
    }
    return self;
}

- (void)flush:(NSString*)requestId
{
    (void)requestId;
    //default dispatcher does not cache any event
    //so here is empty
}

- (void)receive:(NSString *)requestId
          event:(id<ADTelemetryEventInterface>)event
{
    (void)requestId;
    NSDictionary* properties = [event getProperties];
    if (properties)
    {
        [_dispatcher dispatchEvent:properties];
    }
}

@end
