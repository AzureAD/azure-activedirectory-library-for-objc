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
#import "ADLogger.h"
#import "ADErrorCodes.h"
#import "MSIDAuthority.h"
#import "MSIDADFSAuthority.h"

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

- (void)addClientMetrics:(NSMutableDictionary *)requestHeaders
                endpoint:(NSString *)endPoint
{    
    __auto_type adfsAuthority = [[MSIDADFSAuthority alloc] initWithURL:[NSURL URLWithString:endPoint] context:nil error:nil];
    BOOL isADFSInstance = adfsAuthority != nil;

    if (isADFSInstance) return;
    
    @synchronized(self)
    {
        if (!_isPending)
        {
            return;
        }
        
        if (_errorToReport && _responseTime && _endpoint && _correlationId)
        {
            [requestHeaders setObject:_errorToReport forKey:HeaderLastError];
            [requestHeaders setObject:_responseTime forKey:HeaderLastResponseTime];
            [requestHeaders setObject:[ADHelpers getEndpointName:_endpoint] forKey:HeaderLastEndpoint];
            [requestHeaders setObject:_correlationId forKey:HeaderLastRequest];
        }
        else
        {
            MSID_LOG_ERROR(nil, @"unable to add client metrics.");
        }
        
        _errorToReport = nil;
        _endpoint = nil;
        _correlationId = nil;
        _responseTime = nil;
        
        _isPending = NO;
    }
}

- (void)endClientMetricsRecord:(NSString *)endpoint
                     startTime:(NSDate *)startTime
                 correlationId:(NSUUID *)correlationId
                  errorDetails:(NSString *)errorDetails
{
    __auto_type adfsAuthority = [[MSIDADFSAuthority alloc] initWithURL:[NSURL URLWithString:endpoint] context:nil error:nil];
    BOOL isADFSInstance = adfsAuthority != nil;
    if (isADFSInstance) return;
    
    @synchronized(self)
    {
        _endpoint = endpoint;
        _errorToReport = [NSString msidIsStringNilOrBlank:errorDetails] ? @"" : errorDetails;
        _correlationId = [correlationId UUIDString];
        _responseTime = [NSString stringWithFormat:@"%f", [startTime timeIntervalSinceNow] * -1000.0];
        _isPending = YES;
    }
}

- (void)clearMetrics
{
    @synchronized (self)
    {
        _errorToReport = nil;
        _endpoint = nil;
        _correlationId = nil;
        _responseTime = nil;
        
        _isPending = NO;
    }
}

@end
