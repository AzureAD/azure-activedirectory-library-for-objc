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

#import "ADTelemetryPiiRules.h"
#import "ADTelemetryEventStrings.h"

@interface ADTelemetryPiiRules()

@property (nonatomic) NSDictionary *piiRules;

@end

@implementation ADTelemetryPiiRules

#pragma mark - Public

+ (ADTelemetryPiiRules *)sharedInstance
{
    static dispatch_once_t onceToken;
    static id instance;
    
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    
    return instance;
}

- (BOOL)isPii:(NSString *)propertyName
{
    NSNumber *value = self.piiRules[propertyName];
    if (value)
    {
        return [value boolValue];
    }
    
    return NO;
}

#pragma mark - Private

- (NSDictionary *)piiRules
{
    if (!_piiRules)
    {
        _piiRules = @{ AD_TELEMETRY_KEY_USER_ID: @YES};
    }
    
    return _piiRules;
}

@end
