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

#import "ADTelemetryCollectionRules.h"
#import "ADTelemetryEventStrings.h"

static NSDictionary *_telemetryEventRules;

@implementation ADTelemetryCollectionRules

+ (void)initialize
{
    _telemetryEventRules = @{
                             // Collect only
                             AD_TELEMETRY_KEY_AUTHORITY_TYPE: @(CollectOnly),
                             AD_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING: @(CollectOnly),
                             AD_TELEMETRY_KEY_PROMPT_BEHAVIOR: @(CollectOnly),
                             AD_TELEMETRY_KEY_RESULT_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_IDP: @(CollectOnly),
                             AD_TELEMETRY_KEY_TENANT_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_USER_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_START_TIME: @(CollectOnly),
                             AD_TELEMETRY_KEY_END_TIME: @(CollectOnly),
                             AD_TELEMETRY_KEY_RESPONSE_TIME: @(CollectOnly),
                             AD_TELEMETRY_KEY_DEVICE_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_APPLICATION_NAME: @(CollectOnly),
                             AD_TELEMETRY_KEY_APPLICATION_VERSION: @(CollectOnly),
                             AD_TELEMETRY_KEY_LOGIN_HINT: @(CollectOnly),
                             AD_TELEMETRY_KEY_BROKER_VERSION: @(CollectOnly),
                             AD_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION: @(CollectOnly),
                             AD_TELEMETRY_KEY_BROKER_APP: @(CollectOnly),
                             AD_TELEMETRY_KEY_BROKER_APP_USED: @(CollectOnly),
                             AD_TELEMETRY_KEY_CLIENT_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_API_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_TOKEN_TYPE: @(CollectOnly),
                             AD_TELEMETRY_KEY_RT_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_MRRT_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_FRT_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_IS_SUCCESSFUL: @(CollectOnly),
                             AD_TELEMETRY_KEY_CORRELATION_ID: @(CollectOnly),
                             AD_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN: @(CollectOnly),
                             AD_TELEMETRY_KEY_API_ERROR_CODE: @(CollectOnly),
                             AD_TELEMETRY_KEY_PROTOCOL_CODE: @(CollectOnly),
                             AD_TELEMETRY_KEY_ERROR_DESCRIPTION: @(CollectOnly),
                             AD_TELEMETRY_KEY_ERROR_DOMAIN: @(CollectOnly),
                             AD_TELEMETRY_KEY_HTTP_METHOD: @(CollectOnly),
                             AD_TELEMETRY_KEY_HTTP_PATH: @(CollectOnly),
                             AD_TELEMETRY_KEY_HTTP_RESPONSE_METHOD: @(CollectOnly),
                             AD_TELEMETRY_KEY_REQUEST_QUERY_PARAMS: @(CollectOnly),
                             AD_TELEMETRY_KEY_USER_AGENT: @(CollectOnly),
                             AD_TELEMETRY_KEY_HTTP_ERROR_DOMAIN: @(CollectOnly),
                             AD_TELEMETRY_KEY_AUTHORITY: @(CollectOnly),
                             AD_TELEMETRY_KEY_GRANT_TYPE: @(CollectOnly),
                             AD_TELEMETRY_KEY_API_STATUS: @(CollectOnly),
                             AD_TELEMETRY_KEY_EVENT_NAME: @(CollectOnly),
                             AD_TELEMETRY_KEY_REQUEST_ID: @(CollectOnly),
                             
                             // Collect and count
                             AD_TELEMETRY_KEY_UI_EVENT_COUNT: @(CollectAndCount),
                             AD_TELEMETRY_KEY_HTTP_EVENT_COUNT: @(CollectAndCount),
                             AD_TELEMETRY_KEY_CACHE_EVENT_COUNT: @(CollectAndCount),
                             
                             /* Collect and update */
                             // CacheEvent
                             AD_TELEMETRY_KEY_IS_RT: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_IS_MRRT: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_IS_FRT: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_SPE_INFO: @(CollectAndUpdate),
                             // HTTPEvent
                             AD_TELEMETRY_KEY_HTTP_RESPONSE_CODE: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_HTTP_REQUEST_ID_HEADER: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_OAUTH_ERROR_CODE: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_SERVER_ERROR_CODE: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_SERVER_SUBERROR_CODE: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_RT_AGE: @(CollectAndUpdate),
                             // UIEvent
                             AD_TELEMETRY_KEY_USER_CANCEL: @(CollectAndUpdate),
                             AD_TELEMETRY_KEY_NTLM_HANDLED: @(CollectAndUpdate)
                             };
}

+ (ADTelemetryCollectionBehavior)getTelemetryCollectionRule:(NSString *)propertyName
{
    return [[_telemetryEventRules objectForKey:propertyName] intValue];
}

@end
