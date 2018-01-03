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
NSString *const AD_TELEMETRY_EVENT_API_EVENT              = @"Microsoft.ADAL.api_event";
NSString *const AD_TELEMETRY_EVENT_UI_EVENT               = @"Microsoft.ADAL.ui_event";
NSString *const AD_TELEMETRY_EVENT_HTTP_REQUEST           = @"Microsoft.ADAL.http_event";
NSString *const AD_TELEMETRY_EVENT_LAUNCH_BROKER          = @"Microsoft.ADAL.broker_event";
NSString *const AD_TELEMETRY_EVENT_TOKEN_GRANT            = @"Microsoft.ADAL.token_grant";
NSString *const AD_TELEMETRY_EVENT_AUTHORITY_VALIDATION   = @"Microsoft.ADAL.authority_validation";
NSString *const AD_TELEMETRY_EVENT_ACQUIRE_TOKEN_SILENT   = @"Microsoft.ADAL.acquire_token_silent_handler";
NSString *const AD_TELEMETRY_EVENT_ACQUIRE_TOKEN_BY_REFRESH_TOKEN   = @"Microsoft.ADAL.acquire_token_by_refresh_token";
NSString *const AD_TELEMETRY_EVENT_AUTHORIZATION_CODE     = @"Microsoft.ADAL.authorization_code";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_LOOKUP     = @"Microsoft.ADAL.token_cache_lookup";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_WRITE      = @"Microsoft.ADAL.token_cache_write";
NSString *const AD_TELEMETRY_EVENT_TOKEN_CACHE_DELETE     = @"Microsoft.ADAL.token_cache_delete";

// Telemetry property name, only alphabetic letters, dots, and underscores are allowed.
NSString *const AD_TELEMETRY_KEY_EVENT_NAME                   = @"Microsoft.ADAL.event_name";
NSString *const AD_TELEMETRY_KEY_AUTHORITY_TYPE               = @"Microsoft.ADAL.authority_type";
NSString *const AD_TELEMETRY_KEY_AUTHORITY_VALIDATION_STATUS  = @"Microsoft.ADAL.authority_validation_status";
NSString *const AD_TELEMETRY_KEY_EXTENDED_EXPIRES_ON_SETTING  = @"Microsoft.ADAL.extended_expires_on_setting";
NSString *const AD_TELEMETRY_KEY_PROMPT_BEHAVIOR              = @"Microsoft.ADAL.prompt_behavior";
NSString *const AD_TELEMETRY_KEY_RESULT_STATUS                = @"Microsoft.ADAL.status";
NSString *const AD_TELEMETRY_KEY_IDP                          = @"Microsoft.ADAL.idp";
NSString *const AD_TELEMETRY_KEY_TENANT_ID                    = @"Microsoft.ADAL.tenant_id";
NSString *const AD_TELEMETRY_KEY_USER_ID                      = @"Microsoft.ADAL.user_id";
NSString *const AD_TELEMETRY_KEY_START_TIME                   = @"Microsoft.ADAL.start_time";
NSString *const AD_TELEMETRY_KEY_END_TIME                     = @"Microsoft.ADAL.stop_time";
NSString *const AD_TELEMETRY_KEY_RESPONSE_TIME                = @"Microsoft.ADAL.response_time";
NSString *const AD_TELEMETRY_KEY_DEVICE_ID                    = @"Microsoft.ADAL.device_id";
NSString *const AD_TELEMETRY_KEY_APPLICATION_NAME             = @"Microsoft.ADAL.application_name";
NSString *const AD_TELEMETRY_KEY_APPLICATION_VERSION          = @"Microsoft.ADAL.application_version";
NSString *const AD_TELEMETRY_KEY_LOGIN_HINT                   = @"Microsoft.ADAL.login_hint";
NSString *const AD_TELEMETRY_KEY_NTLM_HANDLED                 = @"Microsoft.ADAL.ntlm";
NSString *const AD_TELEMETRY_KEY_UI_EVENT_COUNT               = @"Microsoft.ADAL.ui_event_count";
NSString *const AD_TELEMETRY_KEY_BROKER_APP                   = @"Microsoft.ADAL.broker_app";
NSString *const AD_TELEMETRY_KEY_BROKER_VERSION               = @"Microsoft.ADAL.broker_version";
NSString *const AD_TELEMETRY_KEY_BROKER_PROTOCOL_VERSION      = @"Microsoft.ADAL.broker_protocol_version";
NSString *const AD_TELEMETRY_KEY_BROKER_APP_USED              = @"Microsoft.ADAL.broker_app_used";
NSString *const AD_TELEMETRY_KEY_CLIENT_ID                    = @"Microsoft.ADAL.client_id";
NSString *const AD_TELEMETRY_KEY_HTTP_EVENT_COUNT             = @"Microsoft.ADAL.http_event_count";
NSString *const AD_TELEMETRY_KEY_CACHE_EVENT_COUNT            = @"Microsoft.ADAL.cache_event_count";
NSString *const AD_TELEMETRY_KEY_API_ID                       = @"Microsoft.ADAL.api_id";
NSString *const AD_TELEMETRY_KEY_TOKEN_TYPE                   = @"Microsoft.ADAL.token_type";
NSString *const AD_TELEMETRY_KEY_IS_RT                        = @"Microsoft.ADAL.is_rt";
NSString *const AD_TELEMETRY_KEY_IS_MRRT                      = @"Microsoft.ADAL.is_mrrt";
NSString *const AD_TELEMETRY_KEY_IS_FRT                       = @"Microsoft.ADAL.is_frt";
NSString *const AD_TELEMETRY_KEY_RT_STATUS                    = @"Microsoft.ADAL.token_rt_status";
NSString *const AD_TELEMETRY_KEY_MRRT_STATUS                  = @"Microsoft.ADAL.token_mrrt_status";
NSString *const AD_TELEMETRY_KEY_FRT_STATUS                    = @"Microsoft.ADAL.token_frt_status";
NSString *const AD_TELEMETRY_KEY_IS_SUCCESSFUL                = @"Microsoft.ADAL.is_successfull";
NSString *const AD_TELEMETRY_KEY_CORRELATION_ID               = @"Microsoft.ADAL.correlation_id";
NSString *const AD_TELEMETRY_KEY_IS_EXTENED_LIFE_TIME_TOKEN   = @"Microsoft.ADAL.is_extended_life_time_token";
NSString *const AD_TELEMETRY_KEY_API_ERROR_CODE               = @"Microsoft.ADAL.api_error_code";
NSString *const AD_TELEMETRY_KEY_PROTOCOL_CODE                = @"Microsoft.ADAL.error_protocol_code";
NSString *const AD_TELEMETRY_KEY_ERROR_DESCRIPTION            = @"Microsoft.ADAL.error_description";
NSString *const AD_TELEMETRY_KEY_ERROR_DOMAIN                 = @"Microsoft.ADAL.error_domain";
NSString *const AD_TELEMETRY_KEY_HTTP_METHOD                  = @"Microsoft.ADAL.method";
NSString *const AD_TELEMETRY_KEY_HTTP_PATH                    = @"Microsoft.ADAL.http_path";
NSString *const AD_TELEMETRY_KEY_HTTP_REQUEST_ID_HEADER       = @"Microsoft.ADAL.x_ms_request_id";
NSString *const AD_TELEMETRY_KEY_HTTP_RESPONSE_CODE           = @"Microsoft.ADAL.response_code";
NSString *const AD_TELEMETRY_KEY_OAUTH_ERROR_CODE             = @"Microsoft.ADAL.oauth_error_code";
NSString *const AD_TELEMETRY_KEY_HTTP_RESPONSE_METHOD         = @"Microsoft.ADAL.response_method";
NSString *const AD_TELEMETRY_KEY_REQUEST_QUERY_PARAMS         = @"Microsoft.ADAL.query_params";
NSString *const AD_TELEMETRY_KEY_USER_AGENT                   = @"Microsoft.ADAL.user_agent";
NSString *const AD_TELEMETRY_KEY_HTTP_ERROR_DOMAIN            = @"Microsoft.ADAL.http_error_domain";
NSString *const AD_TELEMETRY_KEY_AUTHORITY                    = @"Microsoft.ADAL.authority";
NSString *const AD_TELEMETRY_KEY_GRANT_TYPE                   = @"Microsoft.ADAL.grant_type";
NSString *const AD_TELEMETRY_KEY_API_STATUS                   = @"Microsoft.ADAL.api_status";
NSString *const AD_TELEMETRY_KEY_REQUEST_ID                   = @"Microsoft.ADAL.request_id";
NSString *const AD_TELEMETRY_KEY_USER_CANCEL                  = @"Microsoft.ADAL.user_cancel";
NSString *const AD_TELEMETRY_KEY_SERVER_ERROR_CODE            = @"Microsoft.ADAL.server_error_code";
NSString *const AD_TELEMETRY_KEY_SERVER_SUBERROR_CODE         = @"Microsoft.ADAL.server_sub_error_code";
NSString *const AD_TELEMETRY_KEY_RT_AGE                       = @"Microsoft.ADAL.rt_age";
NSString *const AD_TELEMETRY_KEY_SPE_INFO                     = @"Microsoft.ADAL.spe_info";

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


