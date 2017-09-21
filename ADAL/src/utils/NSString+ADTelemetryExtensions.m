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

#import "NSString+ADTelemetryExtensions.h"
#import "ADTelemetryEventStrings.h"

#define AD_CLIENT_TELEMETRY_VERSION_NUMBER @"1"

#define CHECK_AND_SET_OBJ(_DICT, _OBJECT, _KEY) \
    if (![NSString adIsStringNilOrBlank:_OBJECT]) \
    { \
        [_DICT setObject:_OBJECT forKey:_KEY]; \
    } \

#define CHECK_AND_SET_OBJ_IF_NOT_ZERO(_DICT, _OBJECT, _KEY) \
    if (![NSString adIsStringNilOrBlank:_OBJECT] && ![_OBJECT isEqualToString:@"0"]) \
    { \
        [_DICT setObject:_OBJECT forKey:_KEY]; \
    } \

@implementation NSString (ADTelemetryExtensions)

- (NSDictionary *)parsedClientTelemetry
{
    NSMutableDictionary *telemetryDict = [NSMutableDictionary dictionary];
    
    if (![NSString adIsStringNilOrBlank:self])
    {
        NSArray *telemetryComponents = [self componentsSeparatedByString:@","];
        
        // Check that there's exactly 5 components
        if ([telemetryComponents count] == 5)
        {
            // Check that the version number is supported
            if ([telemetryComponents[0] isEqualToString:AD_CLIENT_TELEMETRY_VERSION_NUMBER])
            {
                // Fill in the data
                CHECK_AND_SET_OBJ_IF_NOT_ZERO(telemetryDict, telemetryComponents[1], AD_TELEMETRY_KEY_SERVER_ERROR_CODE);
                CHECK_AND_SET_OBJ_IF_NOT_ZERO(telemetryDict, telemetryComponents[2], AD_TELEMETRY_KEY_SERVER_SUBERROR_CODE);
                CHECK_AND_SET_OBJ(telemetryDict, telemetryComponents[3], AD_TELEMETRY_KEY_RT_AGE);
                CHECK_AND_SET_OBJ(telemetryDict, telemetryComponents[4], AD_TELEMETRY_KEY_SPE_INFO);
            }
        }
    }
    
    return telemetryDict;
}

@end
