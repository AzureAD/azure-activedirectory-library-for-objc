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
#import "ADTelemetryAPIEvent.h"
#import "ADUserInformation.h"
#import "MSIDTelemetryEventStrings.h"
#import "ADHelpers.h"
#import "ADAL_Internal.h"
#import "MSIDAuthority.h"
#import "MSIDAuthorityFactory.h"

@implementation ADTelemetryAPIEvent

- (void)setResultStatus:(ADAuthenticationResultStatus)status
{
    NSString* statusStr = nil;
    switch (status) {
        case AD_SUCCEEDED:
            statusStr = MSID_TELEMETRY_VALUE_SUCCEEDED;
            [self setProperty:MSID_TELEMETRY_KEY_IS_SUCCESSFUL value:MSID_TELEMETRY_VALUE_YES];
            break;
        case AD_FAILED:
            statusStr = MSID_TELEMETRY_VALUE_FAILED;
            [self setProperty:MSID_TELEMETRY_KEY_IS_SUCCESSFUL value:MSID_TELEMETRY_VALUE_NO];
            break;
        case AD_USER_CANCELLED:
            statusStr = MSID_TELEMETRY_VALUE_CANCELLED;
            [self setProperty:MSID_TELEMETRY_KEY_USER_CANCEL value:MSID_TELEMETRY_VALUE_YES];
            [self setProperty:MSID_TELEMETRY_KEY_IS_SUCCESSFUL value:MSID_TELEMETRY_VALUE_NO];
            break;
        default:
            statusStr = MSID_TELEMETRY_VALUE_UNKNOWN;
    }
    
    [self setProperty:MSID_TELEMETRY_KEY_RESULT_STATUS value:statusStr];
}

- (void)setUserInformation:(ADUserInformation *)userInfo
{
    [self setProperty:MSID_TELEMETRY_KEY_USER_ID value:[userInfo userId]];
    [self setProperty:MSID_TELEMETRY_KEY_TENANT_ID value:[userInfo tenantId]];
    [self setProperty:MSID_TELEMETRY_KEY_IDP value:[userInfo identityProvider]];
}

- (void)setErrorCode:(NSUInteger)errorCode
{
    NSString *errorString = [ADAuthenticationError stringForADErrorCode:(ADErrorCode)errorCode];
    [self setProperty:MSID_TELEMETRY_KEY_API_ERROR_CODE value:errorString];
}

- (void)setProtocolCode:(NSString *)protocolCode
{
    [self setProperty:MSID_TELEMETRY_KEY_PROTOCOL_CODE value:protocolCode];
}

- (void)setAuthority:(NSString *)authorityString
{
    [super setAuthority:authorityString];
    
    __auto_type factory = [MSIDAuthorityFactory new];
     __auto_type authority = [factory authorityFromUrl:[authorityString msidUrl] context:nil error:nil];
    
    // set authority type
    NSString* authorityType = [authority telemetryAuthorityType];
   
    [self setAuthorityType:authorityType];
}

- (void)setPromptBehavior:(ADPromptBehavior)promptBehavior
{
    NSString* promptBehaviorString = nil;
    switch (promptBehavior) {
        case AD_PROMPT_AUTO:
            promptBehaviorString = @"AD_PROMPT_AUTO";
            break;
        case AD_PROMPT_ALWAYS:
            promptBehaviorString = @"AD_PROMPT_ALWAYS";
            break;
        case AD_PROMPT_REFRESH_SESSION:
            promptBehaviorString = @"AD_PROMPT_REFRESH_SESSION";
            break;
        case AD_FORCE_PROMPT:
            promptBehaviorString = @"AD_FORCE_PROMPT";
            break;
        default:
            promptBehaviorString = MSID_TELEMETRY_VALUE_UNKNOWN;
    }
    
    [self setProperty:MSID_TELEMETRY_KEY_PROMPT_BEHAVIOR value:promptBehaviorString];
}

@end
