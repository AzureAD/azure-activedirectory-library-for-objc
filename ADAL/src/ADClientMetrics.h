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

@interface ADClientMetrics : NSObject
{
@private
    NSString* _endpoint;
    NSString* _responseTime;
    NSString* _correlationId;
    NSString* _errorToReport;
    NSDate* _startTime;
    bool _isPending;
}

@property (readonly) NSString* endpoint;
@property (readonly) NSString* responseTime;
@property (readonly) NSString* correlationId;
@property (readonly) NSString* errorToReport;
@property (readonly) NSDate* startTime;
@property bool isPending;

+ (ADClientMetrics *)getInstance;

- (void)addClientMetrics:(NSMutableDictionary *)requestHeaders
                endpoint:(NSString *)endPoint;

- (void)endClientMetricsRecord:(NSString *)endpoint
                     startTime:(NSDate *)startTime
                 correlationId:(NSUUID *)correlationId
                  errorDetails:(NSString *)errorDetails;

- (void)clearMetrics;

@end
