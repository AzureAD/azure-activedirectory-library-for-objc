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

#import "ADTelemetryEventStrings.h"


// Telemetry event name
NSString *const AD_TELEMETRY_EVENT_API_EVENT              = @"api_event";
NSString *const AD_TELEMETRY_EVENT_UI_EVENT               = @"ui_event";
NSString *const AD_TELEMETRY_EVENT_HTTP_REQUEST           = @"http_event";
NSString *const AD_TELEMETRY_EVENT_LAUNCH_BROKER          = @"broker_event";
NSString *const AD_TELEMETRY_EVENT_TOKEN_GRANT            = @"token_grant";
NSString *const AD_TELEMETRY_EVENT_AUTHORITY_VALIDATION   = @"authority_validation";
NSString *const AD_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT   = @"acquire_token_silent_handler";
NSString *const AD_TELEMETRY_EVENT_AUTHORIZATION_CODE     = @"authorization_code";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP     = @"token_cache_lookup";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_WRITE      = @"token_cache_write";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_DELETE     = @"token_cache_delete";

// Telemetry property name
NSString *const AD_TELEMETRY_KEY_EVENT_NAME                   = @"event_name";
NSString *const AD_TELEMETRY_KEY_AUTHORITY_TYPE               = @"authority_type";
NSString *const AD_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS  = @"authority_validation_status";
NSString *const AD_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING  = @"extended_expires_on_setting";
NSString *const AD_TELEMETRY_KEY_PROMPT_BEHAVIOR              = @"prompt_behavior";
NSString *const AD_TELEMETRY_KEY_RESULT_STATUS                = @"status";
NSString *const AD_TELEMETRY_KEY_IDP                          = @"idp";
NSString *const AD_TELEMETRY_KEY_TENANT_ID                    = @"tenant_id";
NSString *const AD_TELEMETRY_KEY_USER_ID                      = @"user_id";
NSString *const AD_TELEMETRY_KEY_START_TIME                   = @"start_time";
NSString *const AD_TELEMETRY_KEY_END_TIME                     = @"end_time";
NSString *const AD_TELEMETRY_KEY_RESPONSE_TIME                = @"response_time";
NSString *const AD_TELEMETRY_KEY_DEVICE_ID                    = @"device_id";
NSString *const AD_TELEMETRY_KEY_APPLICATION_NAME             = @"application_name";
NSString *const AD_TELEMETRY_KEY_APPLICATION_VERSION          = @"application_version";
NSString *const AD_TELEMETRY_KEY_LOGIN_HINT                   = @"login_hint";
NSString *const AD_TELEMETRY_KEY_NTLM_HANDLED                 = @"ntlm";
NSString *const AD_TELEMETRY_KEY_UI_EVENT_COUNT               = @"ui_event_count";
NSString *const AD_TELEMETRY_KEY_BROKER_APP                   = @"broker_app";
NSString *const AD_TELEMETRY_KEY_BROKER_VERSION               = @"broker_version";
NSString *const AD_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION      = @"broker_protocol_version";
NSString *const AD_TELEMETRY_KEY_BROKER_APP_USED              = @"broker_app_used";
NSString *const AD_TELEMETRY_KEY_CLIENT_ID                    = @"client_id";
NSString *const AD_TELEMETRY_KEY_HTTP_EVENT_COUNT             = @"http_event_count";
NSString *const AD_TELEMETRY_KEY_CACHE_EVENT_COUNT            = @"cache_event_count";
NSString *const AD_TELEMETRY_KEY_API_ID                       = @"api_id";
NSString *const AD_TELEMETRY_KEY_TOKEN_TYPE                   = @"token_type";
NSString *const AD_TELEMETRY_KEY_IS_RT                        = @"is_rt";
NSString *const AD_TELEMETRY_KEY_IS_MRRT                      = @"is_mrrt";
NSString *const AD_TELEMETRY_KEY_IS_FRT                       = @"is_frt";
NSString *const AD_TELEMETRY_KEY_RT_STATUS                    = @"token_rt_status";
NSString *const AD_TELEMETRY_KEY_MRRT_STATUS                  = @"token_mrrt_status";
NSString *const AD_TELEMETRY_KEY_FRT_STATUS                    = @"token_frt_status";
NSString *const AD_TELEMETRY_KEY_IS_SUCCESSFUL                = @"is_successfull";
NSString *const AD_TELEMETRY_KEY_CORRELATION_ID               = @"correlation_id";
NSString *const AD_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN   = @"is_extended_life_time_token";
NSString *const AD_TELEMETRY_KEY_ERROR_CODE                   = @"error_code";
NSString *const AD_TELEMETRY_KEY_PROTOCOL_CODE                = @"error_protocol_code";
NSString *const AD_TELEMETRY_KEY_ERROR_DESCRIPTION            = @"error_description";
NSString *const AD_TELEMETRY_KEY_ERROR_DOMAIN                 = @"error_domain";
NSString *const AD_TELEMETRY_KEY_HTTP_METHOD                  = @"method";
NSString *const AD_TELEMETRY_KEY_HTTP_PATH                    = @"http_path";
NSString *const AD_TELEMETRY_KEY_HTTP_REQUEST_ID_HEADER       = @"x-ms-request-id";
NSString *const AD_TELEMETRY_KEY_HTTP_RESPONSE_CODE           = @"response_code";
NSString *const AD_TELEMETRY_KEY_OAUTH_ERROR_CODE             = @"oauth_error_code";
NSString *const AD_TELEMETRY_KEY_HTTP_RESPONSE_METHOD         = @"response_method";
NSString *const AD_TELEMETRY_KEY_REQUEST_QUERY_PARAMS         = @"query_params";
NSString *const AD_TELEMETRY_KEY_USER_AGENT                   = @"user_agent";
NSString *const AD_TELEMETRY_KEY_HTTP_ERROR_DOMAIN            = @"http_error_domain";
NSString *const AD_TELEMETRY_KEY_AUTHORITY                    = @"authority";
NSString *const AD_TELEMETRY_KEY_GRANT_TYPE                   = @"grant_type";
NSString *const AD_TELEMETRY_KEY_API_STATUS                   = @"api_status";
NSString *const AD_TELEMETRY_KEY_REQUEST_ID                   = @"request_id";
NSString *const AD_TELEMETRY_KEY_USER_CANCEL                  = @"user_cancel";

// Telemetry property value
NSString *const AD_TELEMETRY_VALUE_YES                             = @"yes";
NSString *const AD_TELEMETRY_VALUE_NO                              = @"no";
NSString *const AD_TELEMETRY_VALUE_TRIED                           = @"tried";
NSString *const AD_TELEMETRY_VALUE_USER_CANCELLED                  = @"user_cancelled";
NSString *const AD_TELEMETRY_VALUE_NOT_FOUND                       = @"not_found";
NSString *const AD_TELEMETRY_VALUE_ACCESS_TOKEN                    = @"access_token";
NSString *const AD_TELEMETRY_VALUE_MULTI_RESOURCE_REFRESH_TOKEN    = @"multi_resource_refresh_token";
NSString *const AD_TELEMETRY_VALUE_FAMILY_REFRESH_TOKEN            = @"family_refresh_token";
NSString *const AD_TELEMETRY_VALUE_ADFS_TOKEN                      = @"ADFS_access_token_refresh_token";
NSString *const AD_TELEMETRY_VALUE_BY_CODE                         = @"by_code";
NSString *const AD_TELEMETRY_VALUE_BY_REFRESH_TOKEN                = @"by_refresh_token";
NSString *const AD_TELEMETRY_VALUE_SUCCEEDED                       = @"succeeded";
NSString *const AD_TELEMETRY_VALUE_FAILED                          = @"failed";
NSString *const AD_TELEMETRY_VALUE_CANCELLED                       = @"cancelled";
NSString *const AD_TELEMETRY_VALUE_UNKNOWN                         = @"unknown";
NSString *const AD_TELEMETRY_VALUE_AUTHORITY_AAD                   = @"aad";
NSString *const AD_TELEMETRY_VALUE_AUTHORITY_ADFS                  = @"adfs";


