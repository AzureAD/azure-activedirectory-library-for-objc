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

#import <Foundation/Foundation.h>
#import "ADClientMetrics.h"
#import "ADHelpers.h"
#import "NSString+ADHelperMethods.h"

@implementation ADClientMetrics

//header keys
const NSString* HeaderLastError = @"x-client-last-error";
const NSString* HeaderLastRequest = @"x-client-last-request";
const NSString* HeaderLastResponseTime = @"x-client-last-response-time";
const NSString* HeaderLastEndpoint = @"x-client-last-endpoint";

//values
@synthesize endpoint = _endpoint;
@synthesize responseTime = _responseTime;
@synthesize correlationId = _correlationId;
@synthesize startTime = _startTime;
@synthesize errorToReport = _errorToReport;
@synthesize isPending = _isPending;

+ (ADClientMetrics *)getInstance
{
    static ADClientMetrics* instance = nil;
    static dispatch_once_t onceToken = 0;
    @synchronized(self)
    {
        dispatch_once(&onceToken, ^{
            instance = [[ADClientMetrics alloc] init];
        });
    }
    return instance;
}

- (void) beginClientMetricsRecordForEndpoint: (NSString*) endPoint
                               correlationId: (NSString*) correlationId
                               requestHeader: (NSMutableDictionary*) requestHeader
{
    @synchronized(self)
    {
        if ([ADHelpers isADFSInstance:endPoint])
        {
            return;
        }
        if (_isPending)
        {
            [requestHeader setObject:_errorToReport forKey:HeaderLastError];
            [requestHeader setObject:_responseTime forKey:HeaderLastResponseTime];
            [requestHeader setObject:[ADHelpers getEndpointName:_endpoint] forKey:HeaderLastEndpoint];
            [requestHeader setObject:_correlationId forKey:HeaderLastRequest];
            _isPending = NO;
        }
        SAFE_ARC_RELEASE(_endpoint);
        _endpoint = endPoint;
        SAFE_ARC_RETAIN(_endpoint);
        SAFE_ARC_RELEASE(_responseTime);
        _responseTime = @"";
        SAFE_ARC_RETAIN(_responseTime);
        SAFE_ARC_RELEASE(_correlationId);
        _correlationId = correlationId;
        SAFE_ARC_RETAIN(_correlationId);
        SAFE_ARC_RELEASE(_startTime);
        _startTime = [NSDate new];
        SAFE_ARC_RELEASE(_errorToReport);
        _errorToReport = @"";
        SAFE_ARC_RETAIN(_errorToReport);
    }
}


-(void) endClientMetricsRecord: (NSString*) error{
    
    @synchronized(self)
    {
        if([ADHelpers isADFSInstance:_endpoint])
        {
            return;
        }
        
        SAFE_ARC_RELEASE(_errorToReport);
        if([NSString adIsStringNilOrBlank:error])
        {
            _errorToReport = @"";
        }
        else
        {
            _errorToReport = error;
        }
        SAFE_ARC_RETAIN(_errorToReport);
        
        SAFE_ARC_RELEASE(_responseTime);
        _responseTime = [NSString stringWithFormat:@"%f", [_startTime timeIntervalSinceNow] * -1000.0];
        SAFE_ARC_RETAIN(_responseTime);
        _isPending = YES;
    }
}



@end