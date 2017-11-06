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

static NSDictionary *_piiRules;

@implementation ADTelemetryPiiRules

+ (void)initialize
{
    _piiRules = @{
                  AD_TELEMETRY_KEY_AUTHORITY_TYPE: @NO,
                  AD_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS: @NO,
                  AD_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING: @NO,
                  AD_TELEMETRY_KEY_PROMPT_BEHAVIOR: @NO,
                  AD_TELEMETRY_KEY_RESULT_STATUS: @NO,
                  AD_TELEMETRY_KEY_IDP: @NO,
                  AD_TELEMETRY_KEY_TENANT_ID: @YES,
                  AD_TELEMETRY_KEY_USER_ID: @YES,
                  AD_TELEMETRY_KEY_START_TIME: @NO,
                  AD_TELEMETRY_KEY_END_TIME: @NO,
                  AD_TELEMETRY_KEY_RESPONSE_TIME: @NO,
                  AD_TELEMETRY_KEY_DEVICE_ID: @YES,
                  AD_TELEMETRY_KEY_APPLICATION_NAME: @YES,
                  AD_TELEMETRY_KEY_APPLICATION_VERSION: @NO,
                  AD_TELEMETRY_KEY_LOGIN_HINT: @YES,
                  AD_TELEMETRY_KEY_BROKER_VERSION: @NO,
                  AD_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION: @NO,
                  AD_TELEMETRY_KEY_BROKER_APP: @YES,
                  AD_TELEMETRY_KEY_BROKER_APP_USED: @YES,
                  AD_TELEMETRY_KEY_CLIENT_ID: @YES,
                  AD_TELEMETRY_KEY_API_ID: @NO,
                  AD_TELEMETRY_KEY_TOKEN_TYPE: @NO,
                  AD_TELEMETRY_KEY_RT_STATUS: @NO,
                  AD_TELEMETRY_KEY_MRRT_STATUS: @NO,
                  AD_TELEMETRY_KEY_FRT_STATUS: @NO,
                  AD_TELEMETRY_KEY_IS_SUCCESSFUL: @NO,
                  AD_TELEMETRY_KEY_CORRELATION_ID: @NO,
                  AD_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN: @NO,
                  AD_TELEMETRY_KEY_API_ERROR_CODE: @NO,
                  AD_TELEMETRY_KEY_PROTOCOL_CODE: @NO,
                  AD_TELEMETRY_KEY_ERROR_DESCRIPTION: @YES,
                  AD_TELEMETRY_KEY_ERROR_DOMAIN: @NO,
                  AD_TELEMETRY_KEY_HTTP_METHOD: @NO,
                  AD_TELEMETRY_KEY_HTTP_PATH: @YES,
                  AD_TELEMETRY_KEY_HTTP_RESPONSE_METHOD: @NO,
                  AD_TELEMETRY_KEY_REQUEST_QUERY_PARAMS: @YES,
                  AD_TELEMETRY_KEY_USER_AGENT: @YES,
                  AD_TELEMETRY_KEY_HTTP_ERROR_DOMAIN: @YES,
                  AD_TELEMETRY_KEY_AUTHORITY: @YES,
                  AD_TELEMETRY_KEY_GRANT_TYPE: @NO,
                  AD_TELEMETRY_KEY_API_STATUS: @NO,
                  AD_TELEMETRY_KEY_EVENT_NAME: @NO,
                  AD_TELEMETRY_KEY_REQUEST_ID: @NO,
                  AD_TELEMETRY_KEY_SPE_INFO: @NO,
                  AD_TELEMETRY_KEY_UI_EVENT_COUNT: @NO,
                  AD_TELEMETRY_KEY_HTTP_EVENT_COUNT: @NO,
                  AD_TELEMETRY_KEY_CACHE_EVENT_COUNT: @NO,
                  AD_TELEMETRY_KEY_IS_RT: @NO,
                  AD_TELEMETRY_KEY_IS_MRRT: @NO,
                  AD_TELEMETRY_KEY_IS_FRT: @NO,
                  AD_TELEMETRY_KEY_HTTP_RESPONSE_CODE: @NO,
                  AD_TELEMETRY_KEY_HTTP_REQUEST_ID_HEADER: @NO,
                  AD_TELEMETRY_KEY_OAUTH_ERROR_CODE: @NO,
                  AD_TELEMETRY_KEY_SERVER_ERROR_CODE: @NO,
                  AD_TELEMETRY_KEY_SERVER_SUBERROR_CODE: @NO,
                  AD_TELEMETRY_KEY_RT_AGE: @NO,
                  AD_TELEMETRY_KEY_USER_CANCEL: @NO,
                  AD_TELEMETRY_KEY_NTLM_HANDLED: @NO
                  };
}

#pragma mark - Public

+ (BOOL)isPii:(NSString *)propertyName
{
    NSNumber *value = _piiRules[propertyName];
    if (value)
    {
        return [value boolValue];
    }
    
    return NO;
}

@end
