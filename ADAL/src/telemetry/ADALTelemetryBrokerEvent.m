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
#import "ADALTelemetryBrokerEvent.h"
#import "MSIDTelemetryEventStrings.h"

@implementation ADALTelemetryBrokerEvent

- (id)initWithName:(NSString*)eventName
         requestId:(NSString*)requestId
     correlationId:(NSUUID*)correlationId
{
    self = [super initWithName:eventName requestId:requestId correlationId:correlationId];
    if(self)
    {
        //this is the only broker for iOS
        [self setBrokerApp:@"Microsoft Authenticator"];
    }
    
    return self;
}

- (void)setBrokerAppVersion:(NSString*)version
{
    [self setProperty:MSID_TELEMETRY_KEY_BROKER_VERSION value:version];
}

- (void)setBrokerProtocolVersion:(NSString*)version
{
    [self setProperty:MSID_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION value:version];
}

- (void)setResultStatus:(ADALAuthenticationResultStatus)status
{
    NSString* statusStr = nil;
    switch (status) {
        case AD_SUCCEEDED:
            statusStr = MSID_TELEMETRY_VALUE_SUCCEEDED;
            break;
        case AD_FAILED:
            statusStr = MSID_TELEMETRY_VALUE_FAILED;
            break;
        case AD_USER_CANCELLED:
            statusStr = MSID_TELEMETRY_KEY_USER_CANCEL;
            break;
        default:
            statusStr = MSID_TELEMETRY_VALUE_UNKNOWN;
    }
    
    [self setProperty:MSID_TELEMETRY_KEY_RESULT_STATUS value:statusStr];
}

- (void)setBrokerApp:(NSString*)appName
{
    [self setProperty:MSID_TELEMETRY_KEY_BROKER_APP value:appName];
}

@end
