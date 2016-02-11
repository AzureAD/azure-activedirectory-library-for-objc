// Copyright © Microsoft Open Technologies, Inc.
//
// All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

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