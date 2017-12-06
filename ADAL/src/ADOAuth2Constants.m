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

#import "ADOAuth2Constants.h"

NSString *const OAUTH2_ACCESS_TOKEN       = @"access_token";
NSString *const OAUTH2_AUTHORIZATION      = @"authorization";
NSString *const OAUTH2_AUTHORIZE_SUFFIX   = @"/oauth2/authorize";
NSString *const OAUTH2_AUTHORITY           = @"authority";
NSString *const OAUTH2_AUTHORIZATION_CODE = @"authorization_code";
NSString *const OAUTH2_AUTHORIZATION_URI  = @"authorization_uri";
NSString *const OAUTH2_BEARER             = @"Bearer";
NSString *const OAUTH2_CLIENT_ID          = @"client_id";
NSString *const OAUTH2_CODE               = @"code";
NSString *const OAUTH2_ERROR              = @"error";
NSString *const OAUTH2_ERROR_DESCRIPTION  = @"error_description";
NSString *const OAUTH2_EXPIRES_IN         = @"expires_in";
NSString *const OAUTH2_GRANT_TYPE         = @"grant_type";
NSString *const OAUTH2_REDIRECT_URI       = @"redirect_uri";
NSString *const OAUTH2_REFRESH_TOKEN      = @"refresh_token";
NSString *const OAUTH2_RESOURCE           = @"resource";
NSString *const OAUTH2_RESPONSE_TYPE      = @"response_type";
NSString *const OAUTH2_SCOPE              = @"scope";
NSString *const OAUTH2_STATE              = @"state";
NSString *const OAUTH2_TOKEN              = @"token";
NSString *const OAUTH2_TOKEN_SUFFIX       = @"/oauth2/token";
NSString *const OAUTH2_INSTANCE_DISCOVERY_SUFFIX = @"common/discovery/instance";
NSString *const OAUTH2_TOKEN_TYPE         = @"token_type";
NSString *const OAUTH2_LOGIN_HINT         = @"login_hint";
NSString *const OAUTH2_ID_TOKEN           = @"id_token";
NSString *const OAUTH2_CORRELATION_ID_RESPONSE  = @"correlation_id";
NSString *const OAUTH2_CORRELATION_ID_REQUEST   = @"return-client-request-id";
NSString *const OAUTH2_CORRELATION_ID_REQUEST_VALUE = @"client-request-id";
NSString *const OAUTH2_ASSERTION = @"assertion";
NSString *const OAUTH2_SAML11_BEARER_VALUE = @"urn:ietf:params:oauth:grant-type:saml1_1-bearer";
NSString *const OAUTH2_SAML2_BEARER_VALUE = @"urn:ietf:params:oauth:grant-type:saml2-bearer";
NSString *const OAUTH2_SCOPE_OPENID_VALUE = @"openid";

NSString *const ADAL_CLIENT_FAMILY_ID = @"foci";

NSString *const BROKER_MAX_PROTOCOL_VERSION              = @"max_protocol_ver";

NSString *const BROKER_MESSAGE_VERSION          = @"msg_protocol_ver";
NSString *const BROKER_APP_VERSION              = @"x-broker-app-ver";
NSString *const BROKER_RESPONSE_KEY             = @"response";
NSString *const BROKER_HASH_KEY                 = @"hash";

NSString *const ADAL_CLIENT_TELEMETRY           = @"x-ms-clitelem";

//Diagnostic traces sent to the Azure Active Directory servers:
NSString *const ADAL_ID_VERSION           = @"x-client-Ver";

NSString *const AAD_SECURECONVERSATION_LABEL = @"AzureAD-SecureConversation";

NSString *const AUTH_USERNAME_KEY                = @"username";
NSString *const AUTH_CLOUD_INSTANCE_HOST_NAME    = @"cloud_instance_host_name";

//application constants
NSString* const ADAL_BROKER_SCHEME = @"msauth";
NSString* const ADAL_BROKER_APP_REDIRECT_URI = @"urn:ietf:wg:oauth:2.0:oob";
NSString* const ADAL_BROKER_APP_BUNDLE_ID = @"com.microsoft.azureauthenticator";

